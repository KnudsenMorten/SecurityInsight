using System.Text.Json;

namespace SI.Management.Web.Changes;

/// One report of the report x factor matrix: what it is about, the factors that fit it (derived), and its scope parts.
public sealed record ReportFactorRow(string Report, IReadOnlyList<string> Subjects, IReadOnlyList<string> Factors, IReadOnlyList<string> Include,
    IReadOnlyList<string> Exclude, string Disabled, IReadOnlyList<string> ScopeParts, DataModelRow Row);

/// <summary>
/// #541 (6): the Risk factors page's READ view of which risk factors reach which Risk Analysis report. The report side is
/// the data-model template 'report-scope' (one 'report-scope:&lt;report&gt;' item per report: subjects, scope parts, factor
/// include / exclude; the header 'report-scope' defines the subjects); the factor side is the 'risk-factors' items in force.
/// A report's factor set is DERIVED exactly as the engine derives it (engine\risk-analysis\_shared\RA-ScopePreamble.ps1,
/// Get-RAReportFactorSet) -- keep the two in step:
///   * an asset factor fits when a record type its providers map is one of the subjects' record types (a CMDB factor --
///     record type cmdb_ci -- fits every asset subject; a factor without record types fits by the classes of the fields
///     its condition reads), and every field its condition reads exists on one of the report's classes;
///   * a finding factor fits a finding kind it names (findingKinds), and -- when it names assetClasses -- a report on one
///     of them; report_scoped always fits;
///   * then the report's include / exclude exceptions.
/// Changing a report goes through the existing data-model override flow (Review &amp; commit, cfg.ItemOverride).
/// </summary>
public static class ReportFactorMatrix
{
    public const string Template = "report-scope";

    private sealed record Subject(string? Class, string[] RecordTypes, string? Finding);

    /// PURE. The matrix from the data-model rows in force and the field catalog's classes. Empty when the template is not published yet.
    public static IReadOnlyList<ReportFactorRow> Build(IEnumerable<DataModelRow> rows, IReadOnlyDictionary<string, string[]> fieldClasses)
    {
        var list = rows.ToList();
        var subjects = Subjects(list.FirstOrDefault(r => r.ItemKey == Template));
        var factors = new List<JsonElement>();
        foreach (var r in list.Where(r => r.Template == "risk-factors" && r.Item.Length > 0 && r.Effective is not null))
        {
            try { factors.Add(JsonDocument.Parse(r.Effective!).RootElement.Clone()); } catch (JsonException) { }
        }
        var outRows = new List<ReportFactorRow>();
        foreach (var r in list.Where(r => r.Template == Template && r.Item.Length > 0 && r.Effective is not null))
        {
            JsonElement o;
            try { o = JsonDocument.Parse(r.Effective!).RootElement.Clone(); } catch (JsonException) { continue; }
            var subs = Strings(o, "subjects");
            var include = o.TryGetProperty("factors", out var fa) ? Strings(fa, "include") : new List<string>();
            var exclude = o.TryGetProperty("factors", out var fb) ? Strings(fb, "exclude") : new List<string>();
            string disabled = "setting"; var parts = new List<string>();
            if (o.TryGetProperty("scope", out var sc) && sc.ValueKind == JsonValueKind.Object)
                foreach (var p in sc.EnumerateObject())
                {
                    if (p.Name == "disabled") { disabled = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "setting" : "setting"; continue; }
                    if (p.Value.ValueKind == JsonValueKind.True) parts.Add(p.Name);
                }
            outRows.Add(new ReportFactorRow(r.Item, subs, Derive(subs, include, exclude, factors, subjects, fieldClasses), include, exclude, disabled, parts, r));
        }
        return outRows.OrderBy(x => x.Report, StringComparer.Ordinal).ToList();
    }

    /// PURE. The factor ids that fit a report's subjects (see the class summary), then the include / exclude exceptions.
    private static IReadOnlyList<string> Derive(IReadOnlyList<string> subs, IReadOnlyList<string> include, IReadOnlyList<string> exclude,
        IEnumerable<JsonElement> factors, IReadOnlyDictionary<string, Subject> subjects, IReadOnlyDictionary<string, string[]> fieldClasses)
    {
        var rt = new HashSet<string>(StringComparer.Ordinal); var cls = new HashSet<string>(StringComparer.Ordinal); var kinds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in subs)
        {
            if (!subjects.TryGetValue(s, out var d)) continue;
            foreach (var x in d.RecordTypes) rt.Add(x);
            if (!string.IsNullOrEmpty(d.Class)) cls.Add(d.Class);
            if (!string.IsNullOrEmpty(d.Finding)) kinds.Add(d.Finding);
        }
        var anyAsset = rt.Count > 0 || cls.Count > 0;
        var outIds = new List<string>();
        foreach (var f in factors)
        {
            var id = Str(f, "id"); if (string.IsNullOrEmpty(id)) continue;
            if (Str(f, "stage") == "not_used" || Str(f, "state") == "disabled") continue;   // model v2: a disabled factor is not evaluated
            bool fit = false;
            if (Str(f, "appliesTo") == "finding")
            {
                if (id == "report_scoped") fit = true;
                else fit = Strings(f, "findingKinds").Any(kinds.Contains);
                var ac = Strings(f, "assetClasses");
                if (fit && ac.Count > 0 && !ac.Any(cls.Contains)) fit = false;
            }
            else if (subs.Count == 0) fit = true;
            else if (anyAsset)
            {
                var frt = new List<string>();
                if (f.TryGetProperty("providers", out var prov) && prov.ValueKind == JsonValueKind.Object)
                    foreach (var p in prov.EnumerateObject())
                        if (p.Value.ValueKind == JsonValueKind.Array)
                            foreach (var link in p.Value.EnumerateArray()) frt.AddRange(Strings(link, "recordTypes"));
                if (frt.Any(x => rt.Contains(x) || x == "cmdb_ci")) fit = true;
                var perField = Fields(f.TryGetProperty("when", out var w) ? w : default).Where(fieldClasses.ContainsKey).Select(n => fieldClasses[n]).Where(c => c.Length > 0).ToList();
                if (!fit && frt.Count == 0 && perField.SelectMany(c => c).Any(cls.Contains)) fit = true;
                if (fit && cls.Count > 0 && perField.Any(c => !c.Any(cls.Contains))) fit = false;
            }
            if (fit) outIds.Add(id);
        }
        foreach (var i in include) if (!outIds.Contains(i)) outIds.Add(i);
        foreach (var e in exclude) outIds.Remove(e);
        return outIds;
    }

    private static IReadOnlyDictionary<string, Subject> Subjects(DataModelRow? header)
    {
        var d = new Dictionary<string, Subject>(StringComparer.Ordinal);
        var body = header?.Effective ?? header?.TemplateBody;
        if (body is not null)
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("subjects", out var s) && s.ValueKind == JsonValueKind.Object)
                    foreach (var p in s.EnumerateObject())
                    {
                        if (p.Name.StartsWith('$') || p.Value.ValueKind != JsonValueKind.Object) continue;
                        d[p.Name] = new Subject(Str(p.Value, "class"), Strings(p.Value, "recordTypes").ToArray(), Str(p.Value, "finding"));
                    }
            }
            catch (JsonException) { }
        }
        if (d.Count == 0)
        {
            d["identity-user"] = new Subject("identity", new[] { "user" }, null);
            d["service-principal"] = new Subject("identity", new[] { "service_principal" }, null);
            d["managed-identity"] = new Subject("identity", new[] { "service_principal" }, null);
            d["device"] = new Subject("device", new[] { "device" }, null);
            d["azure-resource"] = new Subject("cloud_resource", new[] { "azure_resource" }, null);
            d["public-ip"] = new Subject("public_ip", new[] { "public_ip" }, null);
            d["vulnerability"] = new Subject(null, Array.Empty<string>(), "vulnerability");
            d["recommendation"] = new Subject(null, Array.Empty<string>(), "recommendation");
        }
        return d;
    }

    /// PURE. The problems in one 'report-scope:&lt;report&gt;' override body (empty = accepted): its id is the key, known subjects,
    /// known scope parts, disabled = setting | exclude | include, factor ids plain.
    public static IReadOnlyList<string> Validate(string item, JsonElement o)
    {
        var why = new List<string>();
        var id = Str(o, "id");
        if (!string.Equals(id, item, StringComparison.Ordinal)) why.Add($"id must be '{item}' -- the key names the report");
        var known = Subjects(null);
        foreach (var s in Strings(o, "subjects")) if (!known.ContainsKey(s)) why.Add($"'{s}' is not a subject ({string.Join(", ", known.Keys)})");
        if (o.TryGetProperty("scope", out var sc) && sc.ValueKind == JsonValueKind.Object)
            foreach (var p in sc.EnumerateObject())
            {
                if (p.Name.StartsWith('$')) continue;
                if (p.Name == "disabled") { if ((p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : null) is not ("setting" or "exclude" or "include")) why.Add("disabled must be setting, exclude or include"); continue; }
                if (p.Name is not ("stale" or "tier" or "excludedAssets" or "assetTags" or "configurationIds" or "cves" or "ipRanges")) why.Add($"'{p.Name}' is not a scope part");
                else if (p.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) why.Add($"scope part '{p.Name}' is true or false");
            }
        if (o.TryGetProperty("factors", out var fa) && fa.ValueKind == JsonValueKind.Object)
            foreach (var x in Strings(fa, "include").Concat(Strings(fa, "exclude")))
                if (!System.Text.RegularExpressions.Regex.IsMatch(x, "^[a-z][a-z0-9_]{0,60}$")) why.Add($"'{x}' is not a factor id");
        return why;
    }

    private static IEnumerable<string> Fields(JsonElement c)
    {
        if (c.ValueKind != JsonValueKind.Object) yield break;
        foreach (var g in new[] { "all", "any" })
            if (c.TryGetProperty(g, out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var x in arr.EnumerateArray()) foreach (var f in Fields(x)) yield return f;
                yield break;
            }
        if (Str(c, "field") is { Length: > 0 } fl) yield return fl;
    }

    private static string? Str(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static List<string> Strings(JsonElement o, string p) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
            : new List<string>();
}
