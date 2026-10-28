using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
//  #274 -- THE REPORT DESIGNER'S MODEL (pure, no I/O): the report catalog (cfg.Template + cfg.ItemOverride kind
//  'rareport'), the report templates, custom reports and their contract, the read-only check of a test query, the output
//  scope per destination (kind 'outputscope'), and the Exclusions / Weights editors' documents (#275 G7).
//  Every body is written the way the engine's ConvertTo-SIProJson writes it (ProJson), so a body the editor did not
//  change is the vendor's byte for byte, and an unchanged item is never written.
// =====================================================================================================================

/// <summary>
/// THE JSON writer of the settings layer in C#: a 1:1 mirror of ConvertTo-SIProJson (engine\pro-settings\SI-ProConfig.ps1)
/// -- indented with two spaces per level, ': ' after a name, every control character and the characters YAML refuses
/// unescaped written as \uXXXX (the materialised catalog is read by a YAML parser), an integral number as an integer.
/// <see cref="Canonical"/> is its -Canonical form (keys sorted ordinally, compact): what an item SAYS.
/// </summary>
public static class ProJson
{
    public static string Str(string value)
    {
        var sb = new StringBuilder(value.Length + 2);
        sb.Append('"');
        foreach (var ch in value)
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

    private static string Number(JsonValue v)
    {
        var raw = v.ToJsonString();
        if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l)) return l.ToString(CultureInfo.InvariantCulture);
        var d = double.Parse(raw, NumberStyles.Float, CultureInfo.InvariantCulture);
        if (d == Math.Floor(d) && Math.Abs(d) < 1e15) return ((long)d).ToString(CultureInfo.InvariantCulture);
        return d.ToString("R", CultureInfo.InvariantCulture);
    }

    private static string Scalar(JsonValue v)
    {
        var k = v.GetValueKind();
        return k switch
        {
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            JsonValueKind.Number => Number(v),
            JsonValueKind.String => Str(v.GetValue<string>()),
            _ => Str(v.ToJsonString()),
        };
    }

    /// ConvertTo-SIProJson -Value $v -Level $level.
    public static string Write(JsonNode? v, int level = 0)
    {
        if (v is null) return "null";
        if (v is JsonValue jv) return Scalar(jv);
        var pad = new string(' ', 2 * level);
        var pad1 = new string(' ', 2 * (level + 1));
        if (v is JsonObject o)
        {
            if (o.Count == 0) return "{}";
            return "{\n" + string.Join(",\n", o.Select(p => pad1 + Str(p.Key) + ": " + Write(p.Value, level + 1))) + "\n" + pad + "}";
        }
        var a = (JsonArray)v;
        if (a.Count == 0) return "[]";
        return "[\n" + string.Join(",\n", a.Select(x => pad1 + Write(x, level + 1))) + "\n" + pad + "]";
    }

    /// ConvertTo-SIProJson -Canonical: keys sorted ordinally, compact.
    public static string Canonical(JsonNode? v)
    {
        if (v is null) return "null";
        if (v is JsonValue jv) return Scalar(jv);
        if (v is JsonObject o) return "{" + string.Join(",", o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => Str(p.Key) + ":" + Canonical(p.Value))) + "}";
        return "[" + string.Join(",", ((JsonArray)v).Select(Canonical)) + "]";
    }

    public static JsonNode? Parse(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try { return JsonNode.Parse(body.TrimStart('﻿')); } catch (JsonException) { return null; }
    }

    /// Test-SIProSameItem for JSON: do two bodies say the same thing?
    public static bool Same(string? a, string? b)
    {
        var x = Parse(a); var y = Parse(b);
        if (x is null || y is null) return string.Equals(a?.Trim(), b?.Trim(), StringComparison.Ordinal);
        return Canonical(x) == Canonical(y);
    }

    public static JsonArray Array(IEnumerable<string> items) => new(items.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
}

/// The vocabularies the designer offers -- the reports' own (every shipped report's scopes use exactly these).
public static class ReportVocabulary
{
    /// The severities of a report's SecuritySeverityScope, in #246 rank order.
    public static readonly IReadOnlyList<string> Severities = ["Very High", "High", "Medium-High", "Medium", "Low"];
    /// The tier labels of a report's CriticalityTierLevelScope, tier 0..3 -- the reports' own labels (every shipped report
    /// and Risk Analysis' CriticalityTierLevel use them). NOT the risk index's tier keys ("0".."3"): the index keys on the
    /// SI field, a report scope on the label.
    public static readonly IReadOnlyList<string> Tiers = ["Critical - tier 0", "High - tier 1", "Medium - tier 2", "Low - tier 3"];
    public static readonly IReadOnlyList<string> Domains = ["Endpoint", "Identity", "Azure", "PublicIP"];
    /// The asset kinds a CMDB connector scope offers -- EVERY kind the data holds (#817, owner 2026-10-20: "i should see all
    /// asset kinds incl. public ip + identity ... dont limit options"): the customer ticks what a connector carries; what a
    /// connector reads at all is its own setting (SI_Pro_CmdbSql_Kinds), never narrowed here.
    public static readonly IReadOnlyList<string> AssetKinds = ["endpoint", "identity", "azure", "publicip"];
    /// The kinds the CMDB connectors send today, which the preview counts: the ServiceNow CMDB reads the endpoint and azure
    /// profiles (Invoke-SICmdb.ps1), the SQL CMDB its Kinds setting (default endpoint, azure -- SI-CmdbSqlSync.ps1). A
    /// ticked kind outside these counts nothing, which is what the connector sends.
    public static readonly IReadOnlyList<string> CmdbSentKinds = ["endpoint", "azure"];
    public static readonly Regex Name = new(@"^[A-Za-z0-9_]{1,100}$", RegexOptions.CultureInvariant);
    public static int TierOf(string label) => Tiers.ToList().FindIndex(t => string.Equals(t, label?.Trim(), StringComparison.OrdinalIgnoreCase));
}

public enum ReportOrigin { Vendor, Changed, Own }

/// One report or report template of the catalog as Risk Analysis will read it on its next run.
public sealed record ReportItem(string Key, ReportOrigin Origin, bool Enabled, string Body, string? TemplateBody, string? OverrideState, string? OverrideBody, int SortOrder)
{
    public bool IsTemplate => Key.StartsWith("template/", StringComparison.Ordinal);
    public string Name => Key[(Key.IndexOf('/') + 1)..];
    public JsonObject? Json => ProJson.Parse(Body) as JsonObject;
    /// What the current override row is, in the form the commit checks it against (State[:Body]; "" = no row).
    public string ExpectedOld => OverrideState is null ? "" : OverrideState + (OverrideBody is null ? "" : ":" + OverrideBody);
}

/// Field access on a report / template body.
public static class ReportBody
{
    public static string Text(JsonObject? o, string name) => o?[name] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : o?[name]?.ToJsonString() ?? "";

    public static IReadOnlyList<string> List(JsonObject? o, string name) => o?[name] switch
    {
        JsonArray a => a.Select(x => x is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : x?.ToJsonString() ?? "").ToList(),
        JsonValue v when v.GetValueKind() == JsonValueKind.String => [v.GetValue<string>()],
        _ => Array.Empty<string>(),
    };

    public static string Query(JsonObject? o) => string.Join("\n", List(o, "ReportQuery"));

    /// The report names a template includes (names, or objects with Name / ReportName).
    public static IReadOnlyList<string> Included(JsonObject? o) => o?["ReportsIncluded"] is JsonArray a
        ? a.Select(x => x switch
        {
            JsonValue v when v.GetValueKind() == JsonValueKind.String => v.GetValue<string>(),
            JsonObject io => Text(io, "Name") is { Length: > 0 } n ? n : Text(io, "ReportName"),
            _ => "",
        }).Where(n => n.Length > 0).ToList()
        : Array.Empty<string>();

    /// The tables a query reads (the names of SI and Defender / Entra tables it mentions outside comments).
    public static IReadOnlyList<string> Tables(string query)
    {
        var code = KqlReadOnly.StripCommentsAndStrings(query);
        return Regex.Matches(code, @"\b(SI_[A-Za-z0-9_]+_CL|ExposureGraph(?:Nodes|Edges)|Device[A-Z][A-Za-z]+|Identity[A-Z][A-Za-z]+|AlertInfo|AlertEvidence|SigninLogs|AADSignInEventsBeta|AuditLogs|CloudAppEvents|EmailEvents|SecurityRecommendation|SecurityResources)\b")
            .Select(m => m.Value).Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToList();
    }

    /// The body with its severity and tier scope replaced (every other property, and the order, kept). The lists are
    /// written in the vocabularies' order.
    public static string WithScope(string body, IEnumerable<string> severities, IEnumerable<string> tiers)
    {
        var o = (JsonObject)ProJson.Parse(body)!;
        var sev = severities.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var tl = tiers.ToHashSet(StringComparer.OrdinalIgnoreCase);
        o["SecuritySeverityScope"] = ProJson.Array(ReportVocabulary.Severities.Where(sev.Contains));
        o["CriticalityTierLevelScope"] = ProJson.Array(ReportVocabulary.Tiers.Where(tl.Contains));
        return ProJson.Write(o, 2);
    }

    /// A template body with its included reports replaced (the other properties kept; each included entry keeps its own
    /// object when it was one).
    public static string WithReports(string body, IReadOnlyList<string> reports, string? purpose = null)
    {
        var o = (JsonObject)ProJson.Parse(body)!;
        var old = o["ReportsIncluded"] as JsonArray;
        var byName = new Dictionary<string, JsonNode>(StringComparer.Ordinal);
        if (old is not null)
            foreach (var x in old)
                if (x is JsonObject io && (Text(io, "Name") is { Length: > 0 } n ? n : Text(io, "ReportName")) is { Length: > 0 } nm && !byName.ContainsKey(nm)) byName[nm] = io.DeepClone();
        o["ReportsIncluded"] = new JsonArray(reports.Select(r => byName.TryGetValue(r, out var keep) ? keep : new JsonObject { ["Name"] = r }).ToArray());
        if (purpose is not null) o["ReportPurpose"] = purpose;
        return ProJson.Write(o, 2);
    }

    public static string NewTemplate(string name, string purpose, IReadOnlyList<string> reports) =>
        ProJson.Write(new JsonObject { ["ReportName"] = name, ["ReportPurpose"] = purpose, ["ReportsIncluded"] = new JsonArray(reports.Select(r => (JsonNode)new JsonObject { ["Name"] = r }).ToArray()) }, 2);

    /// A template body under another name (copy / rename).
    public static string Renamed(string body, string name)
    {
        var o = (JsonObject)ProJson.Parse(body)!;
        o["ReportName"] = name;
        return ProJson.Write(o, 2);
    }

    /// A customer's own report: the shipped reports' shape (the input / output names of the RA contract), the query as a
    /// one-item list as the shipped catalog writes it.
    public static string NewReport(string name, string purpose, string domain, string query, IEnumerable<string> severities, IEnumerable<string> tiers, IReadOnlyList<string>? outputOrder = null)
    {
        var o = new JsonObject { ["ReportName"] = name, ["ReportPurpose"] = purpose, ["SecurityDomain"] = domain };
        foreach (var (k, v) in ReportContract.InputNames) o[k] = v;
        foreach (var (k, v) in ReportContract.OutputNames) o[k] = v;
        var sev = severities.ToHashSet(StringComparer.OrdinalIgnoreCase); var tl = tiers.ToHashSet(StringComparer.OrdinalIgnoreCase);
        o["CriticalityTierLevelScope"] = ProJson.Array(ReportVocabulary.Tiers.Where(tl.Contains));
        o["SecuritySeverityScope"] = ProJson.Array(ReportVocabulary.Severities.Where(sev.Contains));
        o["OutputPropertyOrder"] = ProJson.Array(outputOrder is { Count: > 0 } ? outputOrder : ReportContract.DefaultOutputOrder);
        o["SortBy"] = ProJson.Array(["RiskScoreTotal_Weighted"]);
        o["ReportQuery"] = ProJson.Array([query.Replace("\r\n", "\n").TrimEnd()]);
        return ProJson.Write(o, 2);
    }

    /// Test-SIProItem's rareport rules: the key names the report; a report has a query, a template includes reports.
    public static IReadOnlyList<string> Validate(string key, string? body)
    {
        var why = new List<string>();
        if (!Regex.IsMatch(key ?? "", @"^(report|template)/[A-Za-z0-9_]{1,100}$")) { why.Add($"'{key}' is not a valid report key"); return why; }
        if (ProJson.Parse(body) is not JsonObject o) { why.Add("a report must be a JSON object"); return why; }
        var name = key[(key.IndexOf('/') + 1)..];
        if (Text(o, "ReportName") != name) why.Add($"ReportName must be '{name}' -- the key names the report");
        if (key.StartsWith("report/", StringComparison.Ordinal))
        {
            if (List(o, "ReportQuery").All(string.IsNullOrWhiteSpace)) why.Add("a report needs a ReportQuery");
        }
        else
        {
            var inc = Included(o);
            if (inc.Count == 0) why.Add("a report template needs at least one report");
            foreach (var n in inc) if (!ReportVocabulary.Name.IsMatch(n)) why.Add($"'{n}' is not a report name");
        }
        return why;
    }
}

/// The template builder's list operations (drag, keyboard and buttons all end here): pure, bounds-checked.
public static class TemplateBuilder
{
    public static IReadOnlyList<string> Add(IReadOnlyList<string> list, string report, int? at = null)
    {
        var l = list.Where(x => x != report).ToList();
        var i = Math.Clamp(at ?? l.Count, 0, l.Count);
        l.Insert(i, report);
        return l;
    }

    public static IReadOnlyList<string> Move(IReadOnlyList<string> list, int from, int to)
    {
        var l = list.ToList();
        if (from < 0 || from >= l.Count) return l;
        var x = l[from]; l.RemoveAt(from);
        l.Insert(Math.Clamp(to, 0, l.Count), x);
        return l;
    }

    public static IReadOnlyList<string> Remove(IReadOnlyList<string> list, string report) => list.Where(x => x != report).ToList();
}

/// <summary>
/// One cfg.ItemOverride write: State 'override' (with Body), 'disable', or 'inherit' (the row is removed). ExpectedOld is
/// the row as the editor saw it (State[:Body], "" = no row): the commit writes nothing when ANY row moved since.
/// </summary>
public sealed record ItemWrite(string Kind, string Key, string State, string? Body, string ExpectedOld, string Describe);

public static class ItemWrites
{
    /// The write that turns the current state of one item into the wanted one, or null when nothing changes. A wanted body
    /// that says what the vendor's template says is no override at all (back to the vendor).
    public static ItemWrite? For(string kind, string key, string? templateBody, string? curState, string? curBody, string? wantBody, bool enabled, string describe)
    {
        var old = curState is null ? "" : curState + (curBody is null ? "" : ":" + curBody);
        string state; string? body = null;
        if (!enabled) state = templateBody is null ? "inherit" : "disable";
        else if (templateBody is not null && wantBody is not null && ProJson.Same(wantBody, templateBody)) state = "inherit";
        else if (wantBody is null) state = "inherit";
        else { state = "override"; body = wantBody; }
        var now = curState ?? "inherit";
        if (now == "inherit" && state == "inherit") return null;
        if (now == "disable" && state == "disable") return null;
        if (now == "override" && state == "override" && ProJson.Same(curBody, body)) return null;
        return new ItemWrite(kind, key, state, body, old, describe);
    }
}

/// <summary>
/// THE Risk Analysis report contract, as the engine reads it -- not invented here. xunit checks each list against its
/// source: the input / output names every shipped report declares (RiskAnalysis_Queries_Locked.yaml), Calculate-RiskScore's
/// risk-factor inputs (engine\risk-analysis\_shared\RA-RiskScore.ps1), the engine-set columns ($ComputedCols, $TraceCols of
/// Invoke-RiskAnalysis.ps1) and the canonical order (risk-analysis.schema.locked.json outputColumns).
/// </summary>
public static class ReportContract
{
    /// The five columns a report's rows must carry (the report's *InputName -> the column).
    public static readonly IReadOnlyList<(string Field, string Column)> InputNames =
    [
        ("CategoryInputName", "Category"), ("SubcategoryInputName", "Subcategory"), ("ConfigurationIdInputName", "ConfigurationId"),
        ("SecuritySeverityInputName", "SecuritySeverity"), ("CriticalityTierLevelInputName", "CriticalityTierLevel"),
    ];
    public static readonly IReadOnlyList<(string Field, string Column)> OutputNames =
    [
        ("RiskConsequenceScoreOutputName", "RiskConsequenceScore"), ("RiskProbabilityScoreOutputName", "RiskProbabilityScore"), ("RiskScoreOutputName", "RiskScoreTotal"),
    ];
    /// Optional numeric inputs the score adds (Calculate-RiskScore -RiskFactor*InputName defaults).
    public static readonly IReadOnlyList<string> RiskFactorInputs = ["RiskFactor_Consequence", "RiskFactor_Probability"];
    /// Written by the engine on every row; a query's own value is overwritten.
    public static readonly IReadOnlyList<string> EngineScores = ["RiskConsequenceScore", "RiskProbabilityScore", "RiskScoreTotal", "RiskScoreTotal_Weighted", "RiskScore_Weight_Factor", "RiskScore_Weight_Detailed", "AssetDetectedInReportName"];
    public static readonly IReadOnlyList<string> EngineMeta = ["CollectionTime", "SolutionVersion", "TraceName", "TraceID"];
    public static readonly IReadOnlyList<string> DefaultOutputOrder =
    [
        "SecurityDomain", "Category", "Subcategory", "ConfigurationName", "ConfigurationId", "AssetName", "AssetId", "Impact", "SecuritySeverity", "CriticalityTier", "CriticalityTierLevel",
        "RiskFactor_Consequence_Detailed", "RiskFactor_Consequence", "RiskFactor_Probability_Detailed", "RiskFactor_Probability", "RiskConsequenceScore", "RiskProbabilityScore", "RiskScoreTotal",
        "RiskScore_Weight_Detailed", "RiskScore_Weight_Factor", "RiskScoreTotal_Weighted", "RiskRating", "AssetDetectedInReportName",
    ];
}

/// One problem of a test run: Error = the report cannot work this way; otherwise a note.
public sealed record ContractIssue(string Message, bool Error);

public static class ContractCheck
{
    /// The rows of a test run against the contract: the five input columns present; engine-set columns noted; the severity
    /// and tier values in the reports' vocabularies (a value outside a report's scope is filtered away by Risk Analysis);
    /// risk factors numeric.
    public static IReadOnlyList<ContractIssue> Check(IReadOnlyList<string> columns, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows)
    {
        var issues = new List<ContractIssue>();
        var cols = columns.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var (_, c) in ReportContract.InputNames)
            if (!cols.Contains(c)) issues.Add(new($"the query returns no {c} column -- Risk Analysis reads it to score and scope every row", true));
        foreach (var c in ReportContract.EngineScores.Concat(ReportContract.EngineMeta))
            if (cols.Contains(c)) issues.Add(new($"{c} is set by Risk Analysis on every row -- the query's own value is replaced", false));
        string? V(IReadOnlyDictionary<string, object?> r, string c) => r.FirstOrDefault(kv => string.Equals(kv.Key, c, StringComparison.OrdinalIgnoreCase)).Value?.ToString();
        var badSev = rows.Select(r => V(r, "SecuritySeverity")).Where(s => !string.IsNullOrWhiteSpace(s) && !ReportVocabulary.Severities.Contains(s!.Trim(), StringComparer.OrdinalIgnoreCase)).Distinct().Take(5).ToList();
        if (badSev.Count > 0) issues.Add(new($"SecuritySeverity values outside the reports' vocabulary ({string.Join(", ", badSev)}) -- they never pass a report's severity scope", false));
        var badTier = rows.Select(r => V(r, "CriticalityTierLevel")).Where(s => !string.IsNullOrWhiteSpace(s) && ReportVocabulary.TierOf(s!) < 0).Distinct().Take(5).ToList();
        if (badTier.Count > 0) issues.Add(new($"CriticalityTierLevel values outside the tier labels ({string.Join(", ", badTier)}) -- they never pass a report's tier scope", false));
        foreach (var rf in ReportContract.RiskFactorInputs)
        {
            var bad = rows.Select(r => V(r, rf)).Where(s => !string.IsNullOrWhiteSpace(s) && !double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out _)).Take(1).ToList();
            if (bad.Count > 0) issues.Add(new($"{rf} must be a number ('{bad[0]}') -- Risk Analysis adds it to the score", true));
        }
        if (rows.Count == 0) issues.Add(new("the query returned no rows -- the columns were read from its schema; check it returns findings on a real estate", false));
        return issues;
    }
}

/// <summary>
/// The read-only guard of a TEST query (#274): Log Analytics queries cannot write, but a control command, a cross-
/// resource reach or an external data source has no place in a report. Comments and string literals are stripped first,
/// so a word inside them never decides. Fail closed on what the guard cannot read.
/// </summary>
public static class KqlReadOnly
{
    private static readonly Regex Refused = new(@"(?ix)\b(externaldata|external_table|cluster\s*\(|database\s*\(|workspace\s*\(|app\s*\(|adx\s*\(|arg\s*\(|evaluate\s+(http_request|http_request_post|sql_request|cosmosdb_sql_request|azure_digital_twins_query_request|python|r)\b)", RegexOptions.CultureInvariant);

    public static string StripCommentsAndStrings(string q)
    {
        var sb = new StringBuilder(q.Length);
        for (var i = 0; i < q.Length; i++)
        {
            var c = q[i];
            if (c == '/' && i + 1 < q.Length && q[i + 1] == '/') { while (i < q.Length && q[i] != '\n') i++; sb.Append('\n'); continue; }
            if (c is '"' or '\'')
            {
                var verbatim = i > 0 && q[i - 1] == '@';
                i++;
                while (i < q.Length && q[i] != c) { if (!verbatim && q[i] == '\\') i++; i++; }
                sb.Append(c).Append(c);
                continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    public static IReadOnlyList<string> Problems(string? query)
    {
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(query)) { why.Add("the query is empty"); return why; }
        if (query.Length > 200_000) { why.Add("the query is longer than 200,000 characters"); return why; }
        var code = StripCommentsAndStrings(query);
        foreach (var stmt in code.Split(';'))
            if (stmt.TrimStart().StartsWith('.')) { why.Add("a control command (a statement starting with '.') is not a query -- only read queries can be tested or saved"); break; }
        foreach (Match m in Refused.Matches(code)) why.Add($"'{Regex.Replace(m.Value, @"\s+", " ")}' reaches outside this workspace or runs external code -- a report reads this workspace only");
        if (code.Trim().TrimEnd(';').Length == 0) why.Add("the query has no statement");
        return why.Distinct().ToList();
    }

    /// The query with a row cap: its last statement + "| take n". The query's own trailing ';' is dropped.
    public static string Capped(string query, int cap) => query.Replace("\r\n", "\n").TrimEnd().TrimEnd(';').TrimEnd() + "\n| take " + cap.ToString(CultureInfo.InvariantCulture);

    /// The query's columns (when it returns no row): its last statement + "| getschema".
    public static string Schema(string query) => query.Replace("\r\n", "\n").TrimEnd().TrimEnd(';').TrimEnd() + "\n| getschema";
}

/// One output destination (engine\_shared\SI-OutputScope.ps1 $SIOutputScopeDestinations).
public sealed record OutputDestination(string Key, string Label, bool Asset, string Help);

/// <summary>
/// The output scope of one destination -- the C# twin of SI-OutputScope.ps1 (the same rule, so a preview count is what
/// the engines will send). Empty list = any value; a blank value on a finding passes.
/// </summary>
public sealed record OutputScope(string Destination, IReadOnlyList<string> Templates, IReadOnlyList<string> Reports, IReadOnlyList<string> Severities,
    IReadOnlyList<int> Tiers, IReadOnlyList<string> Domains, IReadOnlyList<string> AssetKinds)
{
    public static readonly IReadOnlyList<OutputDestination> Destinations =
    [
        new("excel", "Excel + mail", false, "What Risk Analysis's own workbook, JSON file, AI summary and mail show. Log Analytics -- and so every connector -- still receives every finding."),
        new("vuln-sql", "Vulnerability connector (SQL)", false, "Which CVE findings the vulnerability close-loop opens in a SQL vulnerability table. A finding outside the scope is never opened -- and one already open is left as it is, never closed by the scope."),
        new("vuln-servicenow", "Vulnerability connector (ServiceNow)", false, "Which CVE findings the vulnerability close-loop opens in ServiceNow (e.g. High and above, tier 0-1 only). Out of scope = not sent; records already there are left as they are."),
        new("cmdb-sql", "CMDB connector (SQL)", true, "Which assets the SQL CMDB connector writes as CIs. An asset outside the scope is not written, and a CI already in the table is left as it is (never retired by the scope)."),
        new("cmdb-servicenow", "CMDB connector (ServiceNow)", true, "Which assets the ServiceNow CMDB connector plans and enriches."),
    ];

    public static OutputDestination? Find(string key) => Destinations.FirstOrDefault(d => d.Key == key);
    public bool IsAsset => Find(Destination)?.Asset == true;
    public bool Everything => Templates.Count + Reports.Count + Severities.Count + Tiers.Count + Domains.Count + AssetKinds.Count + Filters.Count == 0;

    /// Owner 2026-10-19: the filters on the finding's other SI fields (risk rating, class, component ...), by field name.
    public IReadOnlyList<ScopeFilter> Filters { get; init; } = Array.Empty<ScopeFilter>();

    public static OutputScope Empty(string dest) => new(dest, [], [], [], [], [], []);

    public static OutputScope? FromBody(string dest, string? body)
    {
        if (ProJson.Parse(body) is not JsonObject o) return null;
        IReadOnlyList<string> L(string n) => ReportBody.List(o, n).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
        var tiers = L("tiers").Select(t => int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : -1).Where(n => n >= 0).ToList();
        var filters = new List<ScopeFilter>();
        if (o["filters"] is JsonObject fo)
            foreach (var (field, node) in fo.OrderBy(p => p.Key, StringComparer.Ordinal))
            {
                var vals = ReportBody.List(node as JsonObject, "values").Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
                if (vals.Count == 0) continue;
                filters.Add(new ScopeFilter(field, vals));
            }
        return new OutputScope(dest, L("templates"), L("reports"), L("severities"), tiers, L("domains"), L("assetKinds")) { Filters = filters };
    }

    /// The body stored (ConvertTo-SIProJson form): only the lists that narrow; a CMDB destination takes tiers + kinds.
    public string ToBody()
    {
        var o = new JsonObject();
        if (IsAsset)
        {
            if (Tiers.Count > 0) o["tiers"] = new JsonArray(Tiers.OrderBy(t => t).Select(t => (JsonNode?)JsonValue.Create(t)).ToArray());
            if (AssetKinds.Count > 0) o["assetKinds"] = ProJson.Array(ReportVocabulary.AssetKinds.Where(k => AssetKinds.Contains(k, StringComparer.OrdinalIgnoreCase)));
            return ProJson.Write(o);
        }
        if (Templates.Count > 0) o["templates"] = ProJson.Array(Templates);
        if (Reports.Count > 0) o["reports"] = ProJson.Array(Reports);
        if (Severities.Count > 0) o["severities"] = ProJson.Array(ReportVocabulary.Severities.Where(s => Severities.Contains(s, StringComparer.OrdinalIgnoreCase)));
        if (Tiers.Count > 0) o["tiers"] = new JsonArray(Tiers.OrderBy(t => t).Select(t => (JsonNode?)JsonValue.Create(t)).ToArray());
        if (Domains.Count > 0) o["domains"] = ProJson.Array(ReportVocabulary.Domains.Where(d => Domains.Contains(d, StringComparer.OrdinalIgnoreCase)));
        if (Filters.Count > 0)
        {
            var fo = new JsonObject();
            foreach (var f in Filters.OrderBy(f => f.Field, StringComparer.Ordinal))
                fo[f.Field] = new JsonObject { ["values"] = ProJson.Array(ScopeFilters.Ordered(f.Field, f.Values)) };
            o["filters"] = fo;
        }
        return ProJson.Write(o);
    }

    /// Test-SIOutputScopeBody's rules.
    public IReadOnlyList<string> Validate(IReadOnlyCollection<string> knownTemplates, IReadOnlyCollection<string> knownReports)
    {
        var why = new List<string>();
        var d = Find(Destination);
        if (d is null) { why.Add($"'{Destination}' is not a destination"); return why; }
        if (d.Asset && (Templates.Count + Reports.Count + Severities.Count + Domains.Count) > 0) why.Add($"{d.Label} takes an asset scope only (tiers, asset kinds)");
        if (!d.Asset && AssetKinds.Count > 0) why.Add($"{d.Label} takes no asset kinds");
        foreach (var t in Tiers) if (t is < 0 or > 3) why.Add($"'{t}' is not a tier (0, 1, 2 or 3)");
        foreach (var s in Severities) if (!ReportVocabulary.Severities.Contains(s, StringComparer.OrdinalIgnoreCase)) why.Add($"'{s}' is not a severity");
        foreach (var x in Domains) if (!ReportVocabulary.Domains.Contains(x, StringComparer.OrdinalIgnoreCase)) why.Add($"'{x}' is not a security domain");
        foreach (var k in AssetKinds) if (!ReportVocabulary.AssetKinds.Contains(k, StringComparer.OrdinalIgnoreCase)) why.Add($"'{k}' is not an asset kind the CMDB connectors read");
        if (d.Asset && Filters.Count > 0) why.Add($"{d.Label} takes an asset scope only (tiers, asset kinds)");
        foreach (var f in Filters) why.AddRange(ScopeFilters.Validate(f));
        foreach (var t in Templates) if (!knownTemplates.Contains(t)) why.Add($"the report template '{t}' does not exist");
        foreach (var r in Reports) if (!knownReports.Contains(r)) why.Add($"the report '{r}' does not exist");
        return why;
    }

    /// The reports that pass (templates resolved with the catalog's membership), or null = any report.
    public IReadOnlySet<string>? Resolved(IReadOnlyDictionary<string, IReadOnlyList<string>> membership)
    {
        if (Templates.Count + Reports.Count == 0) return null;
        var set = new HashSet<string>(Reports, StringComparer.Ordinal);
        foreach (var t in Templates) if (membership.TryGetValue(t, out var m)) set.UnionWith(m);
        return set;
    }

    public static string Key(string? severity)
    {
        var k = new string((severity ?? "").Trim().ToLowerInvariant().Where(c => c is not (' ' or '-' or '_')).ToArray());
        return k switch { "critical" => "veryhigh", "moderate" => "medium", "info" or "information" => "informational", _ => k };
    }

    /// Test-SIOutputScopeFinding -- with <paramref name="fields"/> the row's values for the filters (field -> its value(s));
    /// null = the filters are not checked (a caller that checks the old dimensions only).
    public bool Passes(string? severity, int? tier, string? domain, string? report, IReadOnlySet<string>? resolved, IReadOnlyDictionary<string, IReadOnlyList<string?>>? fields = null)
    {
        if (fields is not null && !PassesFilters(fields)) return false;
        if (Severities.Count > 0 && Key(severity) is { Length: > 0 } k && !Severities.Select(Key).Contains(k)) return false;
        if (Tiers.Count > 0 && tier is { } t && !Tiers.Contains(t)) return false;
        if (Domains.Count > 0 && !string.IsNullOrWhiteSpace(domain) && !Domains.Contains(domain.Trim(), StringComparer.OrdinalIgnoreCase)) return false;
        if (resolved is not null && !string.IsNullOrWhiteSpace(report) && !resolved.Contains(report.Trim())) return false;
        return true;
    }

    /// Test-SIOutputScopeFilters: OR within a filter (any of the row's values is one of the filter's, case does not count),
    /// AND across filters; a row without a value does not pass.
    public bool PassesFilters(IReadOnlyDictionary<string, IReadOnlyList<string?>> fields)
    {
        foreach (var f in Filters)
        {
            var have = fields.TryGetValue(f.Field, out var v) ? v.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!.Trim()).ToList() : new List<string>();
            if (have.Count == 0) return false;
            if (!have.Any(h => f.Values.Contains(h, StringComparer.OrdinalIgnoreCase))) return false;
        }
        return true;
    }

    /// Test-SIOutputScopeAsset.
    public bool PassesAsset(int? tier, string? kind)
    {
        if (Tiers.Count > 0 && tier is { } t && !Tiers.Contains(t)) return false;
        if (AssetKinds.Count > 0 && !string.IsNullOrWhiteSpace(kind) && !AssetKinds.Contains(kind.Trim(), StringComparer.OrdinalIgnoreCase)) return false;
        return true;
    }

    public string Describe()
    {
        if (Everything) return "everything (no scope)";
        var p = new List<string>();
        if (Templates.Count > 0) p.Add("templates " + string.Join(", ", Templates));
        if (Reports.Count > 0) p.Add("reports " + string.Join(", ", Reports));
        if (Severities.Count > 0) p.Add("severity " + string.Join(", ", Severities));
        if (Tiers.Count > 0) p.Add("tier " + string.Join(", ", Tiers));
        if (Domains.Count > 0) p.Add("domain " + string.Join(", ", Domains));
        if (AssetKinds.Count > 0) p.Add("asset kind " + string.Join(", ", AssetKinds));
        foreach (var f in Filters) p.Add(ScopeFilters.Label(f.Field).ToLowerInvariant() + " " + string.Join(", ", f.Values));
        return string.Join("; ", p);
    }
}

/// A group of findings of the newest collection (the preview counts per destination).
public sealed record FindingGroup(string? Report, string? Domain, string? Severity, int? Tier, bool IsCve, long Count);
public sealed record AssetGroup(string? Kind, int? Tier, long Count);

public static class OutputPreview
{
    public static long Findings(OutputScope s, IReadOnlyList<FindingGroup> groups, IReadOnlyDictionary<string, IReadOnlyList<string>> membership)
    {
        var res = s.Resolved(membership);
        var cveOnly = s.Destination.StartsWith("vuln-", StringComparison.Ordinal);
        return groups.Where(g => (!cveOnly || g.IsCve) && s.Passes(g.Severity, g.Tier, g.Domain, g.Report, res)).Sum(g => g.Count);
    }

    public static long Assets(OutputScope s, IReadOnlyList<AssetGroup> groups) =>
        groups.Where(g => ReportVocabulary.CmdbSentKinds.Contains((g.Kind ?? "").ToLowerInvariant()) && s.PassesAsset(g.Tier, g.Kind)).Sum(g => g.Count);
}

// =====================================================================================================================
//  #275 G7 -- the Exclusions and Weights editors' documents (cfg.Document 'exclusions/<report|global>', 'weights/solution';
//  cfg.ItemOverride 'weights/report/<R>'). The lists are edited; every other property of the document (notes, comments)
//  is kept as it was.
// =====================================================================================================================

public sealed record ExclusionLists(IReadOnlyList<string> Cves, IReadOnlyList<string> ConfigurationIds, IReadOnlyList<string> AssetTags, int? CveMinAgeDays);

public static class ExclusionDocument
{
    public static ExclusionLists Read(string? body)
    {
        var o = ProJson.Parse(body) as JsonObject;
        int? age = o?["CveMinAgeDays"] is JsonValue v && double.TryParse(v.ToJsonString().Trim('"'), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? (int)d : null;
        return new ExclusionLists(ReportBody.List(o, "ExcludedCves"), ReportBody.List(o, "ExcludedConfigurationIds"), ReportBody.List(o, "ExcludedAssetTags"), age);
    }

    /// The document with its lists replaced (blank / repeated entries dropped, order kept); an emptied list is removed;
    /// notes kept. A list the document did not have and the edit leaves empty stays absent.
    public static string Write(string? original, ExclusionLists lists, bool global)
    {
        var o = ProJson.Parse(original) as JsonObject ?? new JsonObject();
        void Set(string name, IReadOnlyList<string> items)
        {
            var clean = items.Select(s => s.Trim()).Where(s => s.Length > 0).Distinct(StringComparer.Ordinal).ToList();
            if (clean.Count == 0) o.Remove(name); else o[name] = ProJson.Array(clean);
        }
        Set("ExcludedAssetTags", lists.AssetTags);
        if (!global)
        {
            Set("ExcludedCves", lists.Cves.Select(c => c.Trim().ToUpperInvariant()).ToList());
            Set("ExcludedConfigurationIds", lists.ConfigurationIds);
            if (lists.CveMinAgeDays is { } a && (a > 0 || o.ContainsKey("CveMinAgeDays"))) o["CveMinAgeDays"] = a; else o.Remove("CveMinAgeDays");
        }
        return ProJson.Write(o);
    }
}

public sealed record WeightField(string Field, IReadOnlyList<(string Value, string Multiplier)> Map, string Default);
public sealed record WeightEngine(string Engine, string Combine, string MaxMultiplier, IReadOnlyList<WeightField> Fields);

public static class WeightsDocument
{
    public static IReadOnlyList<string> Combines => ["product", "max", "sum-of-deltas"];

    /// The weightedRiskFactors of a weights body, per engine (DocumentValidator.WeightEngines order).
    public static IReadOnlyList<WeightEngine> Read(string? body)
    {
        var w = (ProJson.Parse(body) as JsonObject)?["weightedRiskFactors"] as JsonObject;
        var list = new List<WeightEngine>();
        if (w is null) return list;
        foreach (var (name, node) in w)
        {
            if (name.StartsWith('_') || node is not JsonObject e) continue;
            var fields = (e["fields"] as JsonArray)?.OfType<JsonObject>().Select(f => new WeightField(
                ReportBody.Text(f, "field"),
                (f["valueMap"] as JsonObject)?.Select(kv => (kv.Key, kv.Value is JsonValue jv ? jv.ToJsonString().Trim('"') : "")).ToList() ?? new List<(string, string)>(),
                f["default"] is JsonValue dv ? dv.ToJsonString().Trim('"') : "")).ToList() ?? new List<WeightField>();
            list.Add(new WeightEngine(name, ReportBody.Text(e, "combine").Trim('"'), e["maxMultiplier"] is JsonValue mv ? mv.ToJsonString().Trim('"') : "", fields));
        }
        return list;
    }

    private static JsonNode? Num(string s) => double.TryParse(s?.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d)
        ? (d == Math.Floor(d) && Math.Abs(d) < 1e15 ? JsonValue.Create((long)d) : JsonValue.Create(d)) : JsonValue.Create(s?.Trim() ?? "");

    /// The body with weightedRiskFactors replaced by the grid (an engine with no field is left out); every other property,
    /// and the notes inside each engine / field the grid does not show, kept.
    public static string Write(string? original, IReadOnlyList<WeightEngine> engines)
    {
        var o = ProJson.Parse(original) as JsonObject ?? new JsonObject();
        var oldW = o["weightedRiskFactors"] as JsonObject;
        var w = new JsonObject();
        if (oldW is not null) foreach (var (k, v) in oldW) if (k.StartsWith('_')) w[k] = v?.DeepClone();
        foreach (var e in engines.Where(e => e.Fields.Any(f => f.Field.Trim().Length > 0)))
        {
            var old = oldW?[e.Engine] as JsonObject;
            var eo = new JsonObject();
            if (old is not null) foreach (var (k, v) in old) if (k.StartsWith('_')) eo[k] = v?.DeepClone();
            if (!string.IsNullOrWhiteSpace(e.Combine)) eo["combine"] = e.Combine.Trim();
            if (!string.IsNullOrWhiteSpace(e.MaxMultiplier)) eo["maxMultiplier"] = Num(e.MaxMultiplier);
            var oldFields = (old?["fields"] as JsonArray)?.OfType<JsonObject>().ToList() ?? new List<JsonObject>();
            eo["fields"] = new JsonArray(e.Fields.Where(f => f.Field.Trim().Length > 0).Select(f =>
            {
                var fo = new JsonObject();
                var of = oldFields.FirstOrDefault(x => ReportBody.Text(x, "field") == f.Field.Trim());
                if (of is not null) foreach (var (k, v) in of) if (k.StartsWith('_')) fo[k] = v?.DeepClone();
                fo["field"] = f.Field.Trim();
                var map = new JsonObject();
                foreach (var (val, mult) in f.Map) if (val.Trim().Length > 0 && !map.ContainsKey(val.Trim())) map[val.Trim()] = Num(mult);
                fo["valueMap"] = map;
                if (!string.IsNullOrWhiteSpace(f.Default)) fo["default"] = Num(f.Default);
                return (JsonNode)fo;
            }).ToArray());
            w[e.Engine] = eo;
        }
        o["weightedRiskFactors"] = w;
        return ProJson.Write(o);
    }
}
