using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SI.Management.Core.ProData;

namespace SI.Management.Core;

/// A curated tool: name, what it answers, the JSON schema of its arguments, and whether only Admin may call it.
public sealed record ToolSpec(string Name, string Description, string ParametersJsonSchema, bool AdminOnly);

/// What a tool call returned: the result as JSON, and the query it ran.
public sealed record ToolOutput(string ResultJson, string Query, string Source);

/// The ONE list of curated, read-only tools, shared by the MCP server and the chat service so both expose the
/// same names, the same bounds and the same implementations. No free-form query and no write exists here.
public sealed class EstateToolbox
{
    public const string TopRisks = "top_risks";
    public const string AssetLookup = "asset_lookup";
    public const string RiskTrend = "risk_trend";
    public const string DomainTrend = "domain_trend";
    public const string VulnerabilityStateTool = "vulnerability_state";
    public const string RunHealth = "run_health";
    public const string SettingsRead = "settings_read";
    public const string FindingsQuery = "findings_query";
    public const string TrendAnalytics = "trend_analytics";
    public const string VulnLifecycle = "vuln_lifecycle";
    public const string FilterValues = "filter_values";

    public const int DefaultTop = 20;
    public const int DefaultDays = 90;
    public const int DefaultWeeks = 12;
    public const int DefaultRunHealthDays = 7;
    public const int DefaultHistoryRows = 50;
    /// A report list longer than this is not put into a schema enum (the schema stays small); filter_values lists it.
    public const int MaxReportEnum = 30;
    public static readonly TimeSpan ValuesCacheFor = TimeSpan.FromMinutes(10);

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        WriteIndented = false,
    };

    private static string EnumJson(IEnumerable<string> values) => JsonSerializer.Serialize(values.ToArray());

    public static readonly IReadOnlyList<ToolSpec> All =
    [
        new(TopRisks,
            "The highest-risk assets in the newest Risk Analysis snapshot. One machine counts once: names are resolved to one asset id. Ranked by tier (0 = most critical) then weighted risk score.",
            $$$"""{"type":"object","properties":{"top":{"type":"integer","minimum":1,"maximum":{{{QueryParameters.MaxTop}}},"description":"How many assets (default {{{DefaultTop}}})."}},"additionalProperties":false}""",
            false),
        new(AssetLookup,
            "One asset by name or id (host name, FQDN, SecurityInsight asset id, Azure resource id, device id): its tier, type, the other ids it carries, and its top findings.",
            $$$"""{"type":"object","properties":{"nameOrId":{"type":"string","maxLength":{{{QueryParameters.MaxNameOrIdLength}}},"description":"Asset name or id."}},"required":["nameOrId"],"additionalProperties":false}""",
            false),
        new(RiskTrend,
            "Per day: the average risk score per finding (never a sum of scores), the findings, the findings at Very High or High severity, and the tier-0 assets with findings.",
            $$$"""{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":{{{QueryParameters.MaxDays}}},"description":"Days back (default {{{DefaultDays}}})."}},"additionalProperties":false}""",
            false),
        new(DomainTrend,
            "Per day and security domain (Endpoint, Identity, Azure, PublicIP): the average risk score per finding (never a sum of scores) and the findings.",
            $$$"""{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":{{{QueryParameters.MaxDays}}},"description":"Days back (default {{{DefaultDays}}})."}},"additionalProperties":false}""",
            false),
        new(VulnerabilityStateTool,
            "Vulnerability close-loop per week: new, fixed (verified remediated), reopened and open at week end.",
            $$$"""{"type":"object","properties":{"weeks":{"type":"integer","minimum":1,"maximum":{{{QueryParameters.MaxWeeks}}},"description":"Weeks back (default {{{DefaultWeeks}}})."}},"additionalProperties":false}""",
            false),
        new(RunHealth,
            "Engine run heartbeats (start/end, duration, exit reason), newest first.",
            $$$"""{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":{{{QueryParameters.MaxDays}}},"description":"Days back (default {{{DefaultRunHealthDays}}})."}},"additionalProperties":false}""",
            false),
        new(SettingsRead,
            "Admin only. Current non-secret settings and their change history (who changed what, when, why).",
            $$$"""{"type":"object","properties":{"name":{"type":"string","maxLength":128,"description":"One setting name; omit for all."},"days":{"type":"integer","minimum":1,"maximum":{{{QueryParameters.MaxDays}}},"description":"History days back (default {{{DefaultDays}}})."},"rows":{"type":"integer","minimum":1,"maximum":{{{QueryParameters.MaxHistoryRows}}},"description":"Max history rows (default {{{DefaultHistoryRows}}})."}},"additionalProperties":false}""",
            true),
        new(FindingsQuery,
            "Findings of one Risk Analysis collection from the Pro database (the newest unless collectionId is given), filtered and paged. Each row: asset, tier, severity, domain, report, CVE / configuration id, title, risk score. "
            + "'Top vulnerabilities', 'top risks' or 'top N findings' = sort \"risk\" with NO severity filter. Filter values are read ignoring case and common synonyms are mapped (the result's notes say how); "
            + "a filter that matches nothing returns a note listing the values present -- that is NOT proof that none exist.",
            $$$"""{"type":"object","properties":{"collectionId":{"type":"string","maxLength":64,"description":"A collection id (omit for the newest)."},"tier":{"type":"string","enum":{{{EnumJson(ProDataFilters.Tiers)}}},"description":"Asset tier; 0 is the most critical."},"severity":{"type":"string","enum":{{{EnumJson(ToolVocabulary.Severities)}}},"description":"Most severe first. There is no 'Critical' severity: the most severe is 'Very High'."},"domain":{"type":"string","enum":{{{EnumJson(ToolVocabulary.Domains)}}}},"report":{"type":"string","maxLength":200,"description":"Exact Risk Analysis report name, as listed by filter_values."},"assetKind":{"type":"string","enum":{{{EnumJson(ProDataFilters.AssetKinds)}}}},"text":{"type":"string","maxLength":200,"description":"Matched literally in asset name, title, CVE, configuration id, report."},"sort":{"type":"string","enum":{{{EnumJson(FindingSorts.All)}}},"description":"risk = highest risk score first; importance (default) = asset tier, then risk score; severity = Very High first, severity-asc = Low first (by rank, never alphabetical)."},"skip":{"type":"integer","minimum":0,"maximum":100000},"top":{"type":"integer","minimum":1,"maximum":100,"description":"Rows (default 25)."}},"additionalProperties":false}""",
            false),
        new(TrendAnalytics,
            "Trend analytics from the Pro database: findings, assets with findings, the average and the highest risk score per finding, and the Very High + High findings per day, split by one dimension (tier, severity, domain, report or none) and filtered by the others. From the pre-computed daily aggregate; the newest collection of each day counts. "
            + "Filter values are read like findings_query's; a filter that matches nothing returns a note listing the values present.",
            $$$"""{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":730,"description":"Days back (default 90)."},"dimension":{"type":"string","enum":{{{EnumJson(TrendDimensions.All)}}}},"tier":{"type":"string","enum":{{{EnumJson(ProDataFilters.Tiers)}}}},"severity":{"type":"string","enum":{{{EnumJson(ToolVocabulary.Severities)}}}},"domain":{"type":"string","enum":{{{EnumJson(ToolVocabulary.Domains)}}}},"report":{"type":"string","maxLength":200,"description":"Exact report name, as listed by filter_values."}},"additionalProperties":false}""",
            false),
        new(VulnLifecycle,
            "Vulnerability lifecycle from the Pro database: new, closed (verified fixed) and reopened per day, week or month, and open at the end of each period.",
            $$$"""{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":730,"description":"Days back (default 90)."},"grain":{"type":"string","enum":{{{EnumJson(Grains.All)}}},"description":"Grouping (default week)."}},"additionalProperties":false}""",
            false),
        new(FilterValues,
            "The values each findings filter takes in one collection (the newest unless collectionId is given), read from the data: severity (most severe first), tier, security domain, report name and asset kind, plus the sorts. Call it before concluding that something does not exist.",
            """{"type":"object","properties":{"collectionId":{"type":"string","maxLength":64,"description":"A collection id (omit for the newest)."}},"additionalProperties":false}""",
            false),
    ];

    /// The arguments whose values form a fixed or data-driven list; every one carries an enum in its schema (report
    /// only when the data is known and the list is short -- otherwise filter_values lists it).
    public static readonly IReadOnlyList<string> EnumerableArguments = ["severity", "tier", "domain", "assetKind", "sort", "dimension", "grain"];

    private readonly IEstateQueries _q;
    private readonly ISettingsReader _settings;
    private readonly IProDataQueries? _pro;
    private readonly ConcurrentDictionary<string, (DateTimeOffset At, ValueSet Values)> _values = new(StringComparer.Ordinal);

    public EstateToolbox(IEstateQueries queries, ISettingsReader settings, IProDataQueries? proData = null)
    {
        _q = queries;
        _settings = settings;
        _pro = proData;
    }

    /// The tools a caller may see. A Viewer never gets an Admin-only tool.
    public static IReadOnlyList<ToolSpec> For(bool isAdmin) => All.Where(t => isAdmin || !t.AdminOnly).ToList();

    /// The same tools, with the enums of the data-driven arguments (severity, domain, report) read from the newest
    /// collection: the values present are listed, so the model picks a real value instead of guessing one. When the
    /// data cannot be read, the fixed lists stay.
    public async Task<IReadOnlyList<ToolSpec>> SpecsAsync(bool isAdmin, CancellationToken ct)
    {
        var specs = For(isAdmin);
        var v = await TryValuesAsync(null, ct).ConfigureAwait(false);
        if (v is null) return specs;
        return specs.Select(s => s.Name is FindingsQuery or TrendAnalytics ? s with { ParametersJsonSchema = WithEnums(s.ParametersJsonSchema, v) } : s).ToList();
    }

    private static string WithEnums(string schema, ValueSet v)
    {
        var root = JsonNode.Parse(schema)!.AsObject();
        var props = root["properties"]!.AsObject();
        void Set(string arg, IReadOnlyList<string> values)
        {
            if (props[arg] is JsonObject p && values.Count > 0) p["enum"] = new JsonArray(values.Select(x => (JsonNode)JsonValue.Create(x)!).ToArray());
        }
        Set("severity", ToolVocabulary.OrderSeverities(ToolVocabulary.Severities.Concat(v.Severity).Distinct(StringComparer.OrdinalIgnoreCase)));
        Set("domain", ToolVocabulary.Domains.Concat(v.Domain).Distinct(StringComparer.OrdinalIgnoreCase).ToList());
        if (v.Report.Count is > 0 and <= MaxReportEnum) Set("report", v.Report);
        return root.ToJsonString();
    }

    /// Runs one tool by name with JSON arguments. Unknown tools and unknown arguments are refused; an Admin-only
    /// tool called without the Admin role throws UnauthorizedAccessException.
    public async Task<ToolOutput> InvokeAsync(string name, string? argumentsJson, bool isAdmin, CancellationToken ct)
    {
        var spec = All.FirstOrDefault(t => t.Name == name) ?? throw new ArgumentException($"Unknown tool '{name}'.");
        if (spec.AdminOnly && !isAdmin) throw new UnauthorizedAccessException($"'{name}' requires the Admin role.");
        var args = ParseArgs(argumentsJson, spec);

        switch (name)
        {
            // every risk score in an answer is a whole number (the shared ScoreFormat), so a reply quotes it as the pages show it
            case TopRisks: return Out(Map(await _q.TopRisksAsync(args.Int("top", DefaultTop), ct).ConfigureAwait(false),
                d => (IReadOnlyList<TopRisk>)d.Select(x => x with { WeightedRiskScore = ScoreFormat.Round(x.WeightedRiskScore) ?? 0 }).ToList()));
            case AssetLookup: return Out(Map(await _q.AssetLookupAsync(args.Str("nameOrId") ?? throw new ArgumentException("nameOrId is required."), ct).ConfigureAwait(false),
                d => d is null ? null : d with { TopFindings = d.TopFindings.Select(f => f with { RiskScore = ScoreFormat.Round(f.RiskScore) ?? 0 }).ToList() }));
            case RiskTrend: return Out(Map(await _q.RiskTrendAsync(args.Int("days", DefaultDays), ct).ConfigureAwait(false),
                d => (IReadOnlyList<TrendPoint>)d.Select(p => p with { AverageRiskScore = ScoreFormat.Round(p.AverageRiskScore) }).ToList()));
            case DomainTrend: return Out(Map(await _q.DomainTrendAsync(args.Int("days", DefaultDays), ct).ConfigureAwait(false),
                d => (IReadOnlyList<DomainTrendPoint>)d.Select(p => p with { AverageRiskScore = ScoreFormat.Round(p.AverageRiskScore) }).ToList()));
            // no median days to fix in what the assistant is given (owner 2026-10-15: no time to fix in the GUI)
            case VulnerabilityStateTool: return Out(Map(await _q.VulnerabilityStateAsync(args.Int("weeks", DefaultWeeks), ct).ConfigureAwait(false), s => s with { MedianDaysToFix = null }));
            case RunHealth: return Out(await _q.RunHealthAsync(args.Int("days", DefaultRunHealthDays), ct).ConfigureAwait(false));
            case SettingsRead:
                return Out(await _settings.ReadAsync(args.Str("name"), args.Int("days", DefaultDays), args.Int("rows", DefaultHistoryRows), ct).ConfigureAwait(false));
            case FindingsQuery: return await FindingsAsync(args, ct).ConfigureAwait(false);
            case TrendAnalytics: return await TrendAsync(args, ct).ConfigureAwait(false);
            case VulnLifecycle:
            {
                var notes = new List<string>();
                var days = ProDataFilters.Days(args.Int("days", DefaultDays));
                var grain = ToolVocabulary.Pick("grain", args.Str("grain"), Grains.All, ToolVocabulary.GrainWords, Grains.Week, notes);
                // no time to fix (owner 2026-10-15: "remove the time to fix in emails and gui. it makes no value")
                if (_pro is null) return NotConfigured(new { buckets = Array.Empty<LifecycleBucket>() });
                var life = await _pro.LifecycleAsync(days, ct).ConfigureAwait(false);
                return Out(new QueryResult<object>(new { grain, buckets = ProDataQueries.Bucket(life.Data, grain) }, life.Query, life.Source, life.AsOf), notes);
            }
            case FilterValues:
            {
                var collection = ProDataFilters.Id(args.Str("collectionId"), "collection");
                if (_pro is null) return NotConfigured(new { });
                var v = await ValuesAsync(collection, ct).ConfigureAwait(false);
                return Out(new QueryResult<object>(new
                {
                    severity = v.Severity, tier = v.Tier, domain = v.Domain, report = v.Report,
                    assetKind = ProDataFilters.AssetKinds, sort = FindingSorts.All,
                }, v.Query, v.Source, v.AsOf), ["severity is listed most severe first; 'top' findings = sort 'risk' with no severity filter"]);
            }
            default: throw new ArgumentException($"Unknown tool '{name}'.");
        }
    }

    /// What trend_analytics answers per day and group: the risk score per finding (average) and at its highest, and the
    /// findings at the top severities -- the score total is deliberately NOT in the answer, so no reply can quote it.
    public sealed record TrendAnswer(DateOnly Day, string Group, long Findings, long? AssetsWithFindings, double? AverageRiskScore,
        double? HighestRiskScore, long VeryHighOrHighFindings, string? CollectionId)
    {
        public static TrendAnswer From(TrendCell c) => new(c.Day, c.Dimension, c.Findings, c.Assets,
            ScoreFormat.Round(c.ScoreAverage), ScoreFormat.Round(c.ScoreMax), c.TopSeverityFindings, c.CollectionId);
    }

    private static QueryResult<T> Map<T>(QueryResult<T> r, Func<T, T> f) => r with { Data = f(r.Data) };

    private async Task<ToolOutput> FindingsAsync(Args args, CancellationToken ct)
    {
        var notes = new List<string>();
        var collection = ProDataFilters.Id(args.Str("collectionId"), "collection");
        var tier = ToolVocabulary.Strict("tier", args.Str("tier"), ProDataFilters.Tiers, ToolVocabulary.TierWords, notes);
        var kind = ToolVocabulary.Strict("assetKind", args.Str("assetKind"), ProDataFilters.AssetKinds, ToolVocabulary.AssetKindWords, notes);
        var sort = ToolVocabulary.Pick("sort", args.Str("sort"), FindingSorts.All, ToolVocabulary.SortWords, FindingSorts.Importance, notes);
        var rawSeverity = args.Str("severity");
        var rawDomain = args.Str("domain");
        var rawReport = args.Str("report");
        if (_pro is null) return NotConfigured(new FindingPage(Array.Empty<FindingRow>(), 0, 0, 25));

        // the values present are read only when a data-driven filter was given (or the answer comes back empty)
        var v = rawSeverity is null && rawDomain is null && rawReport is null ? null : await TryValuesAsync(collection, ct).ConfigureAwait(false);
        var f = ProDataFilters.Normalize(new FindingFilter
        {
            CollectionId = collection, Tier = tier, AssetKind = kind, Text = args.Str("text"), Sort = sort,
            Severity = ToolVocabulary.Resolve("severity", rawSeverity, v?.Severity, ToolVocabulary.Severities, ToolVocabulary.SeverityWords, notes),
            Domain = ToolVocabulary.Resolve("domain", rawDomain, v?.Domain, ToolVocabulary.Domains, ToolVocabulary.DomainWords, notes),
            Report = ToolVocabulary.Resolve("report", rawReport, v?.Report, Array.Empty<string>(), Array.Empty<(string, string[])>(), notes, containsMatch: true),
            Skip = args.Int("skip", 0), Take = Math.Clamp(args.Int("top", 25), 1, 100),
        });
        var page = await _pro.FindingsAsync(f, ct).ConfigureAwait(false);
        if (page.Data.Total == 0 && page.Data.Rows.Count == 0)
        {
            var filters = Describe(("tier", f.Tier), ("severity", f.Severity), ("domain", f.Domain), ("report", f.Report), ("assetKind", f.AssetKind), ("text", f.Text));
            if (filters.Length == 0)
                notes.Add(f.CollectionId is null ? "the newest collection has no findings at all (no filter was applied)" : $"collection '{f.CollectionId}' has no findings, or does not exist (no filter was applied)");
            else
            {
                v ??= await TryValuesAsync(collection, ct).ConfigureAwait(false);
                notes.Add(NoRows(filters, v, "in this collection"));
            }
        }
        // a risk score in an answer is a whole number (the shared ScoreFormat), as the pages show it
        return Out(Map(page, p => p with { Rows = p.Rows.Select(x => x with { RiskScore = ScoreFormat.Round(x.RiskScore) ?? 0 }).ToList() }), notes);
    }

    private async Task<ToolOutput> TrendAsync(Args args, CancellationToken ct)
    {
        var notes = new List<string>();
        var days = ProDataFilters.Days(args.Int("days", DefaultDays));
        var dim = ToolVocabulary.Pick("dimension", args.Str("dimension"), TrendDimensions.All, ToolVocabulary.DimensionWords, TrendDimensions.Tier, notes);
        var tier = ToolVocabulary.Strict("tier", args.Str("tier"), ProDataFilters.Tiers, ToolVocabulary.TierWords, notes);
        var rawSeverity = args.Str("severity");
        var rawDomain = args.Str("domain");
        var rawReport = args.Str("report");
        if (_pro is null) return NotConfigured(Array.Empty<TrendAnswer>());

        var v = rawSeverity is null && rawDomain is null && rawReport is null ? null : await TryFacetsAsync(ct).ConfigureAwait(false);
        var r = ProDataFilters.Normalize(new TrendRequest
        {
            Days = days, Dimension = dim, Tier = tier,
            Severity = ToolVocabulary.Resolve("severity", rawSeverity, v?.Severity, ToolVocabulary.Severities, ToolVocabulary.SeverityWords, notes),
            Domain = ToolVocabulary.Resolve("domain", rawDomain, v?.Domain, ToolVocabulary.Domains, ToolVocabulary.DomainWords, notes),
            Report = ToolVocabulary.Resolve("report", rawReport, v?.Report, Array.Empty<string>(), Array.Empty<(string, string[])>(), notes, containsMatch: true),
        });
        var cells = await _pro.TrendAsync(r, ct).ConfigureAwait(false);
        if (cells.Data.Count == 0)
        {
            var filters = Describe(("tier", r.Tier), ("severity", r.Severity), ("domain", r.Domain), ("report", r.Report));
            if (filters.Length == 0) notes.Add($"no daily aggregate exists for the last {r.Days} days (no filter was applied)");
            else
            {
                v ??= await TryFacetsAsync(ct).ConfigureAwait(false);
                notes.Add(NoRows(filters, v, "in the last 30 days"));
            }
        }
        // per finding (average, highest) and the top-severity count -- the score total never reaches an answer (#245)
        return Out(new QueryResult<IReadOnlyList<TrendAnswer>>(cells.Data.Select(TrendAnswer.From).ToList(), cells.Query, cells.Source, cells.AsOf), notes);
    }

    private static string Describe(params (string Name, string? Value)[] filters) =>
        string.Join(", ", filters.Where(f => f.Value is not null).Select(f => $"{f.Name}='{f.Value}'"));

    /// The note a filtered query that matched nothing carries: never a bare empty list.
    internal static string NoRows(string filters, ValueSet? v, string where)
    {
        var present = v is null ? "the values present could not be read"
            : $"values present {where}: severity: {ToolVocabulary.List(v.Severity)}; tier: {ToolVocabulary.List(v.Tier)}; domain: {ToolVocabulary.List(v.Domain)}; report: {ToolVocabulary.List(v.Report)}";
        return $"no rows for {filters}; {present}. This does NOT mean none exist: re-query with a value present, or without the filter, before answering.";
    }

    /// The values present, per collection, cached for <see cref="ValuesCacheFor"/>.
    public sealed record ValueSet(IReadOnlyList<string> Severity, IReadOnlyList<string> Tier, IReadOnlyList<string> Domain, IReadOnlyList<string> Report,
        string Query, string Source, DateTimeOffset AsOf);

    private static ValueSet ToSet(QueryResult<IReadOnlyDictionary<string, IReadOnlyList<string>>> r)
    {
        IReadOnlyList<string> Get(string k) => r.Data.TryGetValue(k, out var l) ? l : Array.Empty<string>();
        return new ValueSet(ToolVocabulary.OrderSeverities(Get("severity")), Get("tier").OrderBy(t => t == ProDataFilters.Unclassified ? "9" : t, StringComparer.Ordinal).ToList(),
            Get("domain"), Get("report"), r.Query, r.Source, r.AsOf);
    }

    private async Task<ValueSet> ValuesAsync(string? collectionId, CancellationToken ct)
    {
        var key = "c:" + (collectionId ?? "");
        if (_values.TryGetValue(key, out var hit) && DateTimeOffset.UtcNow - hit.At < ValuesCacheFor) return hit.Values;
        var set = ToSet(await _pro!.CollectionValuesAsync(collectionId, ct).ConfigureAwait(false));
        _values[key] = (DateTimeOffset.UtcNow, set);
        return set;
    }

    private async Task<ValueSet?> TryValuesAsync(string? collectionId, CancellationToken ct)
    {
        if (_pro is null) return null;
        try { return await ValuesAsync(collectionId, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
    }

    private async Task<ValueSet?> TryFacetsAsync(CancellationToken ct)
    {
        if (_pro is null) return null;
        try
        {
            if (_values.TryGetValue("trend", out var hit) && DateTimeOffset.UtcNow - hit.At < ValuesCacheFor) return hit.Values;
            var set = ToSet(await _pro.FacetsAsync(ct).ConfigureAwait(false));
            _values["trend"] = (DateTimeOffset.UtcNow, set);
            return set;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
    }

    private static ToolOutput NotConfigured<T>(T empty) =>
        Out(new QueryResult<T>(empty, "(the Pro data backend is not configured for this server -- Estate:SqlServer / Estate:SqlDatabase)", "not-configured", DateTimeOffset.UtcNow),
            ["the Pro database is not configured for this server: no finding data can be read, which says nothing about the estate"]);

    private static ToolOutput Out<T>(QueryResult<T> r, IReadOnlyList<string>? notes = null) =>
        notes is { Count: > 0 }
            ? new(JsonSerializer.Serialize(new { data = r.Data, query = r.Query, source = r.Source, asOf = r.AsOf, notes }, Json), r.Query, r.Source)
            : new(JsonSerializer.Serialize(new { data = r.Data, query = r.Query, source = r.Source, asOf = r.AsOf }, Json), r.Query, r.Source);

    private sealed class Args(Dictionary<string, JsonElement> values)
    {
        public int Int(string key, int fallback)
        {
            if (!values.TryGetValue(key, out var v) || v.ValueKind == JsonValueKind.Null) return fallback;
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)) return i;
            if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var s)) return s;
            throw new ArgumentException($"'{key}' must be an integer.");
        }

        public string? Str(string key)
        {
            if (!values.TryGetValue(key, out var v) || v.ValueKind == JsonValueKind.Null) return null;
            if (v.ValueKind == JsonValueKind.Number) return v.GetRawText();      // tier 0 sent as a number
            if (v.ValueKind != JsonValueKind.String) throw new ArgumentException($"'{key}' must be a string.");
            var s = v.GetString();
            return string.IsNullOrWhiteSpace(s) ? null : s;
        }
    }

    private static Args ParseArgs(string? json, ToolSpec spec)
    {
        var dict = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(json))
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException("Tool arguments must be a JSON object.");
            using var schema = JsonDocument.Parse(spec.ParametersJsonSchema);
            var allowed = schema.RootElement.GetProperty("properties").EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (!allowed.Contains(p.Name)) throw new ArgumentException($"'{spec.Name}' has no argument '{p.Name}'.");
                dict[p.Name] = p.Value.Clone();
            }
        }
        return new Args(dict);
    }
}
