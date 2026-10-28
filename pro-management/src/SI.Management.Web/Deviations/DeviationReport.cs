using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Deviations;

// ---- the rows the report reads (sql\si-pro-settings.sql) ------------------------------------------------------------
public sealed record DevSetting(string Name, string Scope, string? ValueJson, string? KeyVaultSecretName, DateTime? UpdatedAt, string? UpdatedBy);
public sealed record DevDocument(string Kind, string Key, string? Body, DateTime? UpdatedAt, string? UpdatedBy);
public sealed record DevTemplate(string Kind, string ItemKey, string? TemplateVersion, string? BodyJson);
public sealed record DevOverride(string Kind, string ItemKey, string State, string? BodyJson, DateTime? UpdatedAt, string? UpdatedBy);
public sealed record DevExemption(string ExemptionId, string Scope, string? ReportName, string? ConfigurationId, string? Cve, string? AssetKey,
    string? Reason, DateTime? ExpiresAt, string? CreatedBy, DateTime? CreatedAt, DateTime? RevokedAt);
public sealed record DevChange(long ChangeId, string Name, string Scope, string? Kind, string Action, DateTime? ChangedAt, string? ChangedBy, string? Reason);

public sealed record DeviationInputs(
    IReadOnlyList<DevSetting> Settings, IReadOnlyList<DevDocument> Documents, IReadOnlyList<DevTemplate> Templates,
    IReadOnlyList<DevOverride> Overrides, IReadOnlyList<DevExemption> Exemptions, IReadOnlyList<DevChange> ChangeLog)
{
    public static DeviationInputs Empty { get; } = new(Array.Empty<DevSetting>(), Array.Empty<DevDocument>(), Array.Empty<DevTemplate>(),
        Array.Empty<DevOverride>(), Array.Empty<DevExemption>(), Array.Empty<DevChange>());
}

/// One deviation from the shipped defaults. ChangedAt / ExpiresAt are UTC text ('yyyy-MM-ddTHH:mm:ssZ'), exactly as the
/// PowerShell report writes them. HistoryName / HistoryScope: where its cfg.ChangeLog history is recorded.
public sealed record DeviationRow(string Kind, string Item, string Scope, string ShippedDefault, string Current, string Reason, string Owner,
    string ChangedBy, string? ChangedAt, string? ExpiresAt, string Status, string HistoryName, string HistoryScope)
{
    public DateTime? ChangedAtUtc => DeviationReport.ParseUtc(ChangedAt);
    public DateTime? ExpiresAtUtc => DeviationReport.ParseUtc(ExpiresAt);
}

/// <summary>
/// The C# twin of Get-SIDeviationReport (engine\_shared\SI-DeviationReport.ps1): every deviation from the shipped
/// defaults, one row each -- exemptions, Risk Analysis exclusions, disabled detections, tier moves, item overrides, risk
/// weights, and settings that differ from a KNOWN shipped default (no shipped default = install configuration; a secret
/// is never read). PURE: rows in, rows out. tests\fixtures\deviation-report-cases.json holds both implementations to the
/// same output -- change the rules in both, then the fixture.
/// Connector suppressions: the schema has no table for them yet, so there is nothing to report.
/// </summary>
public static partial class DeviationReport
{
    public const string None = "(none)";
    public static readonly string[] Kinds = ["Exemption", "Exclusion", "DisabledDetection", "TierMove", "ItemOverride", "RiskWeights", "Setting"];
    public static readonly string[] Columns = ["Kind", "Item", "Scope", "ShippedDefault", "Current", "Reason", "Owner", "ChangedBy", "ChangedAt", "ExpiresAt", "Status"];
    public static readonly string[] Statuses = ["active", "expiring", "expired"];

    /// <summary>
    /// #287: THE plain-language name of each kind -- the one map the page's dropdown, tiles and grid and the Excel export
    /// use. The stored kind values (and the CSV, which is the same machine file the PowerShell report writes) do not change.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> KindLabels = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["Exemption"] = "Exemption", ["Exclusion"] = "Exclusion", ["DisabledDetection"] = "Detection turned off", ["TierMove"] = "Tier move",
        ["ItemOverride"] = "Item override", ["RiskWeights"] = "Risk weights", ["Setting"] = "Setting",
    };

    public static string KindLabel(string? kind) => kind is not null && KindLabels.TryGetValue(kind, out var l) ? l : kind ?? "";
    private static readonly string[] DetectionKinds = ["rule", "rareport"];

    [GeneratedRegex(@"^\s*Tier\s*:\s*(\d+)", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TierLine();
    [GeneratedRegex(@"^mode\s*:\s*disable\b", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DisableLine();

    // =================================================================================================================
    //  values
    // =================================================================================================================
    public static string? UtcText(DateTime? v)
    {
        if (v is not { } d) return null;
        var u = d.Kind switch { DateTimeKind.Local => d.ToUniversalTime(), _ => DateTime.SpecifyKind(d, DateTimeKind.Utc) };
        return u.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    }

    public static DateTime? ParseUtc(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null
        : DateTime.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

    public static string Status(DateTime? expiresAt, DateTime now, int expiringDays = 30)
    {
        if (expiresAt is not { } e) return "active";
        var u = e.Kind == DateTimeKind.Local ? e.ToUniversalTime() : DateTime.SpecifyKind(e, DateTimeKind.Utc);
        var n = now.Kind == DateTimeKind.Local ? now.ToUniversalTime() : DateTime.SpecifyKind(now, DateTimeKind.Utc);
        if (u <= n) return "expired";
        if (u <= n.AddDays(expiringDays)) return "expiring";
        return "active";
    }

    /// A string as a JSON literal -- the PowerShell side's own escaping (ConvertTo-SIDevJsonString).
    public static string JsonString(string s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('"');
        foreach (var ch in s)
        {
            var c = (int)ch;
            if (ch == '"') sb.Append("\\\"");
            else if (ch == '\\') sb.Append("\\\\");
            else if (c == 10) sb.Append("\\n");
            else if (c == 13) sb.Append("\\r");
            else if (c == 9) sb.Append("\\t");
            else if (c < 32 || (c >= 0x7F && c <= 0x9F) || c == 0x2028 || c == 0x2029 || c == 0xFEFF) sb.Append("\\u").Append(c.ToString("x4", CultureInfo.InvariantCulture));
            else sb.Append(ch);
        }
        return sb.Append('"').ToString();
    }

    /// Canonical JSON: compact, keys in ordinal order, a whole number without a fraction (25 = 25.0).
    public static string Canonical(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                var props = e.EnumerateObject().ToList();
                if (props.Count == 0) return "{}";
                return "{" + string.Join(",", props.OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => JsonString(p.Name) + ":" + Canonical(p.Value))) + "}";
            case JsonValueKind.Array:
                return "[" + string.Join(",", e.EnumerateArray().Select(Canonical)) + "]";
            case JsonValueKind.String: return JsonString(e.GetString() ?? "");
            case JsonValueKind.Number:
                if (e.TryGetInt64(out var l)) return l.ToString(CultureInfo.InvariantCulture);
                var d = e.GetDouble();
                if (d == Math.Floor(d) && Math.Abs(d) < 1e15) return ((long)d).ToString(CultureInfo.InvariantCulture);
                return d.ToString("R", CultureInfo.InvariantCulture);
            case JsonValueKind.True: return "true";
            case JsonValueKind.False: return "false";
            default: return "null";
        }
    }

    public static bool IsEmpty(JsonElement? e) => e is not { } v
        || v.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined
        || (v.ValueKind == JsonValueKind.String && v.GetString() is "")
        || (v.ValueKind == JsonValueKind.Array && v.GetArrayLength() == 0);

    public static string Display(JsonElement? e) => IsEmpty(e) ? None : Canonical(e!.Value);

    private static JsonElement? ParseOrText(string? json)
    {
        if (json is null) return null;
        try { using var d = JsonDocument.Parse(json); return d.RootElement.Clone(); }
        catch (JsonException) { return JsonSerializer.SerializeToElement(json); }
    }

    private static JsonElement? TryParse(string? json)
    {
        if (json is null) return null;
        try { using var d = JsonDocument.Parse(json.TrimStart('﻿')); return d.RootElement.Clone(); }
        catch (JsonException) { return null; }
    }

    private static bool Eq(string? a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static bool IsNote(string name) => name.StartsWith('_') || Eq(name, "Comment") || Eq(name, "$schema");
    private static JsonElement? Prop(JsonElement o, string name)
    {
        foreach (var p in o.EnumerateObject()) if (Eq(p.Name, name)) return p.Value;
        return null;
    }

    // =================================================================================================================
    //  rules
    // =================================================================================================================
    public static (int[] Tiers, bool Disabled) RuleFacts(string? text)
    {
        var t = text ?? "";
        var tiers = TierLine().Matches(t).Select(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)).Distinct().OrderBy(x => x).ToArray();
        return (tiers, DisableLine().IsMatch(t));
    }

    public static string FormatTiers(IReadOnlyCollection<int> tiers) =>
        tiers.Count == 0 ? "(no tier)" : "tier " + string.Join(", ", tiers.Select(x => x.ToString(CultureInfo.InvariantCulture)));

    public static (string Kind, string Shipped, string Current) RuleClass(string? body, string? shippedBody, string shippedLabel = "shipped rule")
    {
        var has = !string.IsNullOrEmpty(shippedBody);
        var f = RuleFacts(body);
        if (f.Disabled) return ("DisabledDetection", has ? "on" : None, "turned off");
        if (has)
        {
            var s = RuleFacts(shippedBody);
            if (FormatTiers(s.Tiers) != FormatTiers(f.Tiers)) return ("TierMove", FormatTiers(s.Tiers), FormatTiers(f.Tiers));
            return ("ItemOverride", shippedLabel, "overridden");
        }
        return ("ItemOverride", None, "added");
    }

    // =================================================================================================================
    //  document bodies
    // =================================================================================================================
    public static IReadOnlyList<(string Item, string Shipped, string Current)> ExclusionEntries(string? body)
    {
        var o = TryParse(body);
        if (o is not { ValueKind: JsonValueKind.Object } doc) return [("(unreadable)", None, "not a valid JSON object")];
        var list = new List<(string, string, string)>();
        foreach (var p in doc.EnumerateObject())
        {
            if (IsNote(p.Name)) continue;
            if (p.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var x in p.Value.EnumerateArray())
                {
                    if (x.ValueKind is JsonValueKind.Null || (x.ValueKind == JsonValueKind.String && x.GetString() is "")) continue;
                    var text = x.ValueKind == JsonValueKind.String ? x.GetString()! : Canonical(x);
                    list.Add(($"{p.Name}: {text}", "not excluded", "excluded"));
                }
                continue;
            }
            if (IsEmpty(p.Value)) continue;
            var shipped = Eq(p.Name, "CveMinAgeDays") ? "0" : None;
            var cur = Canonical(p.Value);
            if (cur == shipped) continue;
            list.Add((p.Name, shipped, cur));
        }
        return list;
    }

    public static IReadOnlyList<(string Item, string Current)> WeightEntries(string? body)
    {
        var o = TryParse(body);
        if (o is not { ValueKind: JsonValueKind.Object } doc) return [("(unreadable)", "not a valid JSON object")];
        if (Prop(doc, "weightedRiskFactors") is not { ValueKind: JsonValueKind.Object } w) return [];
        var list = new List<(string, string)>();
        foreach (var e in w.EnumerateObject())
        {
            if (e.Name.StartsWith('_') || Eq(e.Name, "Comment") || e.Value.ValueKind == JsonValueKind.Null) continue;
            var n = 0;
            if (e.Value.ValueKind == JsonValueKind.Object && Prop(e.Value, "fields") is { } f)
                n = f.ValueKind switch { JsonValueKind.Array => f.EnumerateArray().Count(x => x.ValueKind != JsonValueKind.Null), JsonValueKind.Null => 0, _ => 1 };
            list.Add(($"weightedRiskFactors/{e.Name}", $"{n} weighted field(s)"));
        }
        return list;
    }

    public static string ExemptionItem(DevExemption e)
    {
        var what = string.IsNullOrEmpty(e.Cve) ? e.ConfigurationId ?? "" : e.Cve;
        return e.Scope.ToLowerInvariant() switch
        {
            "asset" => $"every finding on {e.AssetKey}",
            "issue" => $"{what} on every asset",
            _ => $"{what} on {e.AssetKey}",
        };
    }

    // =================================================================================================================
    //  history
    // =================================================================================================================
    public sealed record History(string? Owner, string? ChangedBy, string? ChangedAt, string? Reason);

    public static string HistoryKey(string? scope, string? kind, string? name) => $"{scope}|{kind}|{name}".ToLowerInvariant();

    public static Dictionary<string, History> HistoryIndex(IEnumerable<DevChange> log)
    {
        var index = new Dictionary<string, History>(StringComparer.Ordinal);
        foreach (var g in log.GroupBy(c => HistoryKey(c.Scope, c.Kind, c.Name), StringComparer.Ordinal))
        {
            string? owner = null, reason = null, by = null, at = null;
            foreach (var c in g.OrderBy(c => c.ChangeId.ToString("D20", CultureInfo.InvariantCulture) + "|" + (UtcText(c.ChangedAt) ?? ""), StringComparer.Ordinal))
            {
                var who = c.ChangedBy ?? "";
                if (c.Action == "Reset") { owner = null; reason = null; }
                else if (owner is null && who.Length > 0) owner = who;
                if (c.Action != "Reset" && !string.IsNullOrWhiteSpace(c.Reason)) reason = c.Reason;
                by = who; at = UtcText(c.ChangedAt);
            }
            index[g.Key] = new History(owner, by, at, reason);
        }
        return index;
    }

    // =================================================================================================================
    //  the report
    // =================================================================================================================
    public static IReadOnlyList<DeviationRow> Build(DeviationInputs input, IEnumerable<CatalogSetting> catalog, DateTime now, int expiringDays = 30)
    {
        var rows = new List<DeviationRow>();
        var hist = HistoryIndex(input.ChangeLog);
        History? H(string scope, string? kind, string name) => hist.TryGetValue(HistoryKey(scope, kind, name), out var h) ? h : null;
        DeviationRow Row(string kind, string item, string scope, string shipped, string current, string? reason, History? h,
                         string? fbOwner, string? fbBy, DateTime? fbAt, DateTime? expires, string hName, string hScope)
        {
            var owner = fbOwner ?? ""; var by = fbBy ?? ""; var at = UtcText(fbAt); var why = reason ?? "";
            if (h is not null)
            {
                if (!string.IsNullOrEmpty(h.Owner)) owner = h.Owner;
                if (!string.IsNullOrEmpty(h.ChangedBy)) by = h.ChangedBy;
                if (!string.IsNullOrEmpty(h.ChangedAt)) at = h.ChangedAt;
                if (why.Length == 0 && !string.IsNullOrEmpty(h.Reason)) why = h.Reason;
            }
            return new DeviationRow(kind, item, scope, shipped, current, why, owner, by, at, UtcText(expires), Status(expires, now, expiringDays), hName, hScope);
        }

        var tpl = new Dictionary<string, DevTemplate>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in input.Templates) tpl[$"{t.Kind}/{t.ItemKey}"] = t;
        static string Label(DevTemplate t) => ("template " + (t.TemplateVersion ?? "")).Trim();

        // ---- settings: a value that differs from a KNOWN shipped default ----
        var cat = new Dictionary<string, CatalogSetting>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in catalog) cat[s.Name] = s;
        foreach (var r in input.Settings)
        {
            if (!string.IsNullOrEmpty(r.KeyVaultSecretName)) continue;
            if (!cat.TryGetValue(r.Name, out var s) || s.Secret) continue;
            if (s.Default is not { } def || def.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined) continue;
            var shipped = Display(def); var cur = Display(ParseOrText(r.ValueJson));
            if (shipped == cur) continue;
            rows.Add(Row("Setting", r.Name, r.Scope, shipped, cur, null, H(r.Scope, null, r.Name), r.UpdatedBy, r.UpdatedBy, r.UpdatedAt, null, r.Name, r.Scope));
        }

        // ---- documents ----
        foreach (var d in input.Documents)
        {
            var h = H("document", d.Kind, d.Key);
            switch (d.Kind.ToLowerInvariant())
            {
                case "exclusions":
                    foreach (var (item, sh, cu) in ExclusionEntries(d.Body))
                        rows.Add(Row("Exclusion", item, d.Key, sh, cu, null, h, d.UpdatedBy, d.UpdatedBy, d.UpdatedAt, null, d.Key, "document"));
                    break;
                case "weights":
                    foreach (var (item, cu) in WeightEntries(d.Body))
                        rows.Add(Row("RiskWeights", item, d.Key, None, cu, null, h, d.UpdatedBy, d.UpdatedBy, d.UpdatedAt, null, d.Key, "document"));
                    break;
                case "rule":
                    tpl.TryGetValue("rule/" + d.Key, out var t);
                    var c = RuleClass(d.Body, t?.BodyJson, t is null ? "" : Label(t));
                    rows.Add(Row(c.Kind, d.Key, "rule", c.Shipped, c.Current, null, h, d.UpdatedBy, d.UpdatedBy, d.UpdatedAt, null, d.Key, "document"));
                    break;
            }
        }

        // ---- item overrides ----
        foreach (var o in input.Overrides)
        {
            var isOverride = Eq(o.State, "override");
            if (!isOverride && !Eq(o.State, "disable")) continue;
            var h = H("item", o.Kind, o.ItemKey);
            DeviationRow R(string kind, string scope, string shipped, string current) =>
                Row(kind, o.ItemKey, scope, shipped, current, null, h, o.UpdatedBy, o.UpdatedBy, o.UpdatedAt, null, o.ItemKey, "item");
            if (Eq(o.Kind, "ruletier"))
            {
                if (!isOverride) continue;
                tpl.TryGetValue("rule/" + o.ItemKey, out var rt);
                var shipped = rt is null ? "(the rule's own tiers)" : FormatTiers(RuleFacts(rt.BodyJson).Tiers);
                string? tier = null;
                if (TryParse(o.BodyJson) is { ValueKind: JsonValueKind.Object } b && Prop(b, "tier") is { } tv)
                    tier = tv.ValueKind switch { JsonValueKind.String => tv.GetString(), JsonValueKind.Null => null, _ => tv.GetRawText() };
                rows.Add(R("TierMove", "ruletier", shipped, string.IsNullOrEmpty(tier) ? "tier ?" : "tier " + tier));
                continue;
            }
            tpl.TryGetValue($"{o.Kind}/{o.ItemKey}", out var t);
            if (!isOverride)
            {
                var k = DetectionKinds.Contains(o.Kind, StringComparer.OrdinalIgnoreCase) ? "DisabledDetection" : "ItemOverride";
                rows.Add(R(k, o.Kind, t is null ? None : "on", "turned off"));
                continue;
            }
            if (Eq(o.Kind, "rule"))
            {
                var c = RuleClass(o.BodyJson, t?.BodyJson, t is null ? "" : Label(t));
                rows.Add(R(c.Kind, "rule", c.Shipped, c.Current));
                continue;
            }
            rows.Add(R("ItemOverride", o.Kind, t is null ? None : Label(t), t is null ? "added" : "overridden"));
        }

        // ---- exemptions: every one not revoked (an expired one is flagged, not hidden) ----
        foreach (var e in input.Exemptions)
        {
            if (e.RevokedAt is not null) continue;
            var hn = "exemption/" + e.ExemptionId;
            rows.Add(Row("Exemption", ExemptionItem(e), string.IsNullOrEmpty(e.ReportName) ? "every report" : e.ReportName, "not exempt",
                $"exempt ({e.Scope})", e.Reason, H("exemption", "exemption", hn), e.CreatedBy, e.CreatedBy, e.CreatedAt, e.ExpiresAt, hn, "exemption"));
        }

        return rows.OrderBy(r => Array.IndexOf(Kinds, r.Kind)).ThenBy(r => r.Scope, StringComparer.Ordinal).ThenBy(r => r.Item, StringComparer.Ordinal).ToList();
    }

    // =================================================================================================================
    //  CSV -- the PowerShell side's ConvertTo-SIDeviationCsv
    // =================================================================================================================
    public static string CsvField(string? v)
    {
        var s = v ?? "";
        if (s.Length > 0 && "=+-@\t\r".Contains(s[0])) s = "'" + s;
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    public static string ToCsv(IEnumerable<DeviationRow> rows)
    {
        var sb = new StringBuilder();
        sb.Append(string.Join(",", Columns)).Append("\r\n");
        foreach (var r in rows)
            sb.Append(string.Join(",", new[] { r.Kind, r.Item, r.Scope, r.ShippedDefault, r.Current, r.Reason, r.Owner, r.ChangedBy, r.ChangedAt, r.ExpiresAt, r.Status }.Select(CsvField))).Append("\r\n");
        return sb.ToString();
    }
}

/// <summary>The page's filters: kind, owner (who introduced it or last changed it), age (of the latest change), expiry.</summary>
public sealed record DeviationFilter(string? Kind = null, string? Owner = null, string? Age = null, string? Expiry = null)
{
    /// Age: changed within 7 / 30 / 90 days, or not changed for more than 90 / 365 days.
    public static readonly string[] Ages = ["7", "30", "90", "older90", "older365"];
    /// Expiry: the row's status, or whether it has an expiry at all.
    public static readonly string[] Expiries = ["active", "expiring", "expired", "has-expiry", "no-expiry"];

    /// Unknown values are dropped, so a query string can only ever narrow by the known choices.
    public DeviationFilter Normalize() => new(
        DeviationReport.Kinds.FirstOrDefault(k => string.Equals(k, Kind, StringComparison.OrdinalIgnoreCase)),
        string.IsNullOrWhiteSpace(Owner) ? null : Owner.Trim(),
        Ages.Contains(Age) ? Age : null,
        Expiries.Contains(Expiry) ? Expiry : null);

    public IEnumerable<DeviationRow> Apply(IEnumerable<DeviationRow> rows, DateTime now)
    {
        var f = Normalize();
        foreach (var r in rows)
        {
            if (f.Kind is not null && r.Kind != f.Kind) continue;
            if (f.Owner is not null && !r.Owner.Contains(f.Owner, StringComparison.OrdinalIgnoreCase) && !r.ChangedBy.Contains(f.Owner, StringComparison.OrdinalIgnoreCase)) continue;
            if (f.Age is not null)
            {
                if (r.ChangedAtUtc is not { } at) continue;
                var days = (now - at).TotalDays;
                var ok = f.Age switch { "7" => days <= 7, "30" => days <= 30, "90" => days <= 90, "older90" => days > 90, "older365" => days > 365, _ => true };
                if (!ok) continue;
            }
            if (f.Expiry is not null)
            {
                var ok = f.Expiry switch { "has-expiry" => r.ExpiresAt is not null, "no-expiry" => r.ExpiresAt is null, var s => r.Status == s };
                if (!ok) continue;
            }
            yield return r;
        }
    }
}

/// <summary>
/// THE EXCEL HOOK. The Deviations page offers "Export to Excel" only when an implementation of this is registered; the
/// web app has no XLSX writer of its own yet (the Excel export work adds one). Register it in Program.cs and the button
/// and the ?handler=Xlsx download light up -- nothing else on the page changes.
/// </summary>
public interface IDeviationWorkbookWriter
{
    /// The workbook bytes for these rows (columns: <see cref="DeviationReport.Columns"/>).
    byte[] Write(IReadOnlyList<DeviationRow> rows, string sheetName);
}
