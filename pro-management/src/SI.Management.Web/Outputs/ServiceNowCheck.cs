using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Data;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Outputs;

/// <summary>
/// THE SERVICENOW SETUP AND ITS CHECKS in the web app (owner 2026-10-20: "a feature to verify the schema in servicenow table
/// matches. and i connect to servicenow + verify connection. verify table schema matches + get alerts + set api key in
/// keyvault + url to instance and what is needed"). One guided place per ServiceNow connector (Configuration &gt; Connectors
/// &gt; Setup): what is needed, ticked from what the install has; the instance URL; the API key (Set value, #822); Verify.
/// <para>
/// THE WEB APP NEVER SIGNS IN TO SERVICENOW: it holds no Key Vault right (the secret hand-over, owner 2026-10-10), so it
/// cannot read the key. "Verify" starts the mail job once (<see cref="ServiceNowVerifier"/>, SI_SNOW_VERIFY), which runs the
/// checks with the engine identity -- the SAME credential path the push uses (engine\asset-cmdb\_shared\SI-SnowVerify.ps1
/// Resolve-SISnowOutputConnection) -- and records each result in cfg.ServiceNowCheck. The page reads the newest result per
/// output and compares the table's columns with the columns IN FORCE (<see cref="ServiceNowSchema"/>, the same schema the
/// ServiceNow team creates the table from): <see cref="ServiceNowSchemaCompare"/>.
/// </para>
/// </summary>
public static class ServiceNowOutputs
{
    /// One ServiceNow output: its connector's direction, the setting that names its Import Set table, its scope destination.
    public sealed record Info(string Output, string Direction, string TableSetting, string Destination, string Label);

    /// #903: both outputs are fed by the ONE ServiceNow data-out connector (direction 'data-out'); each keeps its own table setting.
    public static readonly IReadOnlyList<Info> All =
    [
        new("servicenow-ci", SI.Management.Web.Changes.ServiceNowDataOut.Direction, "SI_DataOut_ServiceNowCiTable", "cmdb-servicenow", "ServiceNow CI hand-off"),
        new("servicenow-vulnerable-item", SI.Management.Web.Changes.ServiceNowDataOut.Direction, "SI_DataOut_ServiceNowVulnTable", "vuln-servicenow", "ServiceNow vulnerable items"),
    ];

    public static Info? Of(string? output) => All.FirstOrDefault(i => i.Output == output);
    /// Every output a connector of <paramref name="direction"/> feeds (data-out: both; any other: none).
    public static IReadOnlyList<Info> OfDirection(string? direction) => All.Where(i => string.Equals(i.Direction, (direction ?? "").Trim(), StringComparison.OrdinalIgnoreCase)).ToList();

    /// The ServiceNow roles the key's user needs, per call -- the engine's $script:SISnowCheckRoles (a test keeps them equal).
    /// From ServiceNow's documentation of the Import Set API and the dictionary tables; confirmed on a real instance before
    /// the feature is called delivered.
    public static readonly IReadOnlyList<(string Call, IReadOnlyList<string> Roles, string Why)> Roles =
    [
        ("send", ["import_set_loader", "import_transformer"], "to send rows through the Import Set API"),
        ("columns", ["personalize_dictionary"], "to read the table and its columns (Verify) -- without it ServiceNow refuses with 403 \"unauthorized to access table: sys_db_object\""),
        ("mapping", ["import_admin"], "optional: to read the REST Insert Multiple column mapping (Verify)"),
    ];

    /// #903: the calls whose role is optional -- the engine's $script:SISnowCheckOptionalCalls (a test keeps them equal).
    public static readonly IReadOnlySet<string> OptionalCalls = new HashSet<string>(StringComparer.Ordinal) { "mapping" };
}

/// <summary>THE INSTANCE URL of a ServiceNow connector: https only, a host name (an instance of service-now.com or your own
/// domain), no path, no query -- normalised to https://host.</summary>
public static class ServiceNowInstanceUrl
{
    public const string Example = "https://<name>.service-now.com";

    /// PURE. (the normalised address, null) or (null, why not -- plain words).
    public static (string? Url, string? Problem) Validate(string? input)
    {
        var t = (input ?? "").Trim();
        if (t.Length == 0) return (null, "enter the instance address, for example " + Example);
        if (t.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return (null, "the instance address must start with https:// (the key would cross the network in clear text)");
        if (!t.Contains("://", StringComparison.Ordinal)) t = "https://" + t;
        if (!Uri.TryCreate(t, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return (null, "not an https address, for example " + Example);
        if (!string.IsNullOrEmpty(u.UserInfo)) return (null, "the address must not carry a user or a password");
        if (!string.IsNullOrEmpty(u.Query) || !string.IsNullOrEmpty(u.Fragment)) return (null, "only the instance's address: no ? or # part");
        if (u.AbsolutePath is not ("/" or "") || t.TrimEnd('/').Count(c => c == '/') > 2) return (null, "only the instance's address: no path (remove everything after the host name)");
        if (u.HostNameType != UriHostNameType.Dns || !u.Host.Contains('.', StringComparison.Ordinal)) return (null, "a host name with a domain, for example " + Example);
        var host = u.Host.ToLowerInvariant();
        return ("https://" + host + (u.IsDefaultPort ? "" : ":" + u.Port.ToString(CultureInfo.InvariantCulture)), null);
    }

    /// Whether the address is an instance on service-now.com (else your own domain).
    public static bool IsServiceNowHost(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Host.EndsWith(".service-now.com", StringComparison.OrdinalIgnoreCase);

    /// PURE. The connector's settings JSON with "instance" set to <paramref name="url"/> (every other setting kept).
    public static string WithInstance(string? settingsJson, string url)
    {
        JsonObject o;
        try { o = JsonNode.Parse(string.IsNullOrWhiteSpace(settingsJson) ? "{}" : settingsJson) as JsonObject ?? new JsonObject(); }
        catch (JsonException) { o = new JsonObject(); }
        o["instance"] = url;
        return o.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
}

/// One column of the Import Set table as ServiceNow describes it (sys_dictionary).
public sealed record SnowColumn(string Name, string Type, int MaxLength, string Label);

/// A check as the engine recorded it (cfg.ServiceNowCheck) -- facts and plain words, never a secret.
public sealed record SnowCheckRow(long CheckId, string Output, string? Connector, string? Table, string Trigger, string? RequestedBy, DateTime? CheckedAt,
    string Outcome, string? Summary, DateTime? NotOkSince, SnowCheckFacts Facts);

/// What one check found (the ResultJson the engine writes, SI-SnowVerify.ps1 ConvertTo-SISnowCheckJson).
public sealed record SnowCheckFacts(bool? ConnectionOk, string ConnectionKind, string ConnectionText, string Role, bool? TableExists, bool? ImportSet,
    bool ColumnsRead, string ColumnsText, IReadOnlyList<SnowColumn> Columns, string Mapping, string MappingText, bool Hold,
    IReadOnlyList<(string Column, string Kind, string Text)> Problems)
{
    public static readonly SnowCheckFacts None = new(null, "", "", "", null, null, false, "", Array.Empty<SnowColumn>(), "", "", false, Array.Empty<(string, string, string)>());

    /// #903: the role ServiceNow refused for reading the columns / the mapping (the check's columns.role / mapping.role; '' = none).
    public string ColumnsRole { get; init; } = "";
    public string MappingRole { get; init; } = "";
    /// How the check reached the instance (its source words, e.g. "the connector x with its API key"; never a secret).
    public string Source { get; init; } = "";
    /// #912 the staging status table as the check found it (statusTable): checked at all, its name, set, exists, the columns missing, the words.
    public bool StatusChecked { get; init; }
    public string StatusTable { get; init; } = "";
    public bool StatusSet { get; init; }
    public bool? StatusExists { get; init; }
    public IReadOnlyList<string> StatusMissing { get; init; } = Array.Empty<string>();
    public string StatusText { get; init; } = "";

    /// PURE. The stored JSON, read leniently (an unreadable result = <see cref="None"/>).
    public static SnowCheckFacts Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return None;
        JsonObject? o;
        try { o = JsonNode.Parse(json) as JsonObject; } catch (JsonException) { return None; }
        if (o is null) return None;
        static string S(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : n is JsonValue x ? x.ToString() : "";
        static bool? B(JsonNode? n) => n is JsonValue v && v.TryGetValue<bool>(out var b) ? b : null;
        static int I(JsonNode? n)
        {
            if (n is not JsonValue v) return 0;
            if (v.TryGetValue<int>(out var i)) return i;
            if (v.TryGetValue<long>(out var l)) return (int)Math.Clamp(l, 0, int.MaxValue);
            return int.TryParse(v.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var j) ? j : 0;
        }
        var c = o["connection"] as JsonObject; var cols = o["columns"] as JsonObject; var m = o["mapping"] as JsonObject;
        var list = (cols?["list"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
            .Select(x => new SnowColumn(S(x["name"]), S(x["type"]), I(x["maxLength"]), S(x["label"]))).Where(x => x.Name.Length > 0).ToList();
        var problems = (o["problems"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().Select(x => (S(x["column"]), S(x["kind"]), S(x["text"]))).ToList();
        return new SnowCheckFacts(B(c?["ok"]), S(c?["kind"]), S(c?["text"]), S(c?["role"]), B(c?["tableExists"]), B(c?["importSet"]),
            B(cols?["read"]) ?? false, S(cols?["text"]), list, S(m?["state"]), S(m?["text"]), B(o["hold"]) ?? false, problems)
        {
            ColumnsRole = S(cols?["role"]), MappingRole = S(m?["role"]), Source = S(o["source"]),
            StatusChecked = o["statusTable"] is JsonObject, StatusTable = S(o["statusTable"]?["table"]), StatusSet = B(o["statusTable"]?["set"]) ?? false,
            StatusExists = B(o["statusTable"]?["exists"]), StatusText = S(o["statusTable"]?["text"]),
            StatusMissing = (o["statusTable"]?["missing"] as JsonArray ?? new JsonArray()).Select(S).Where(x => x.Length > 0).ToList(),
        };
    }
}

public interface IServiceNowCheckStore
{
    /// The newest check of each ServiceNow output (none = never checked, or no table yet).
    Task<IReadOnlyList<SnowCheckRow>> LatestAsync(CancellationToken ct);
}

public sealed class SqlServiceNowCheckStore(ISqlExecutor sql) : IServiceNowCheckStore
{
    /// The newest row per output (by the index on Output, CheckId), and since when it has not been ok.
    public const string LatestSql = """
IF OBJECT_ID(N'cfg.ServiceNowCheck') IS NOT NULL
SELECT c.CheckId, c.[Output], c.Connector, c.TableName, c.[Trigger], c.RequestedBy, c.CheckedAt, c.Outcome, c.Summary, c.ResultJson,
       (SELECT MIN(x.CheckedAt) FROM cfg.ServiceNowCheck AS x
         WHERE x.[Output] = c.[Output] AND x.Outcome <> N'ok'
           AND x.CheckId > ISNULL((SELECT MAX(o.CheckId) FROM cfg.ServiceNowCheck AS o WHERE o.[Output] = c.[Output] AND o.Outcome = N'ok'), 0)) AS NotOkSince
FROM cfg.ServiceNowCheck AS c
WHERE c.CheckId = (SELECT MAX(m.CheckId) FROM cfg.ServiceNowCheck AS m WHERE m.[Output] = c.[Output]);
""";

    public async Task<IReadOnlyList<SnowCheckRow>> LatestAsync(CancellationToken ct) =>
        (await sql.QueryAsync(LatestSql, new Dictionary<string, object?>(), ct)).Select(r => new SnowCheckRow(r.Long("CheckId") ?? 0, r.Str("Output") ?? "",
            r.Str("Connector"), r.Str("TableName"), r.Str("Trigger") ?? "", r.Str("RequestedBy"), r.Date("CheckedAt"), r.Str("Outcome") ?? "", r.Str("Summary"),
            r.Date("NotOkSince"), SnowCheckFacts.Parse(r.Str("ResultJson")))).ToList();
}

/// One line of the schema comparison: the column, what was found, its level (red: a row would lose or cut a value; amber:
/// worth a look; info: fine to leave; ok) and the words.
public sealed record SchemaLine(string Column, string Kind, string Level, string Text);

/// <summary>
/// THE SCHEMA COMPARISON (PURE): the columns IN FORCE of a ServiceNow output (<see cref="ServiceNowSchema.Build"/>: name,
/// type, ServiceNow type, the length to create) against the Import Set table's columns as ServiceNow describes them.
///   missing column      red    its values would be lost
///   too short           red    a text column shorter than the length to create: values would be cut
///   type differs        amber  the value arrives as text the transform has to convert
///   extra column        info   a column of the table SecurityInsight does not send (fine, listed)
///   column mapping      red when ServiceNow matches by label (the rows land empty), amber when it could not be read
/// </summary>
public static class ServiceNowSchemaCompare
{
    public sealed record Expected(string Name, string Type, string ServiceNowType, int MaxLength);

    /// The text types of ServiceNow a value can be written into as text, and the types each schema type accepts.
    private static readonly IReadOnlyDictionary<string, string[]> Accepts = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
    {
        ["string"] = ["string"],
        ["integer"] = ["integer", "longint"],
        ["decimal"] = ["decimal", "float"],
        ["boolean"] = ["boolean"],
        ["glide_date_time"] = ["glide_date_time", "due_date"],
    };

    private static bool IsText(string type) => type is "" or "string";

    /// PURE. The expected columns from a built schema (its "fields").
    public static IReadOnlyList<Expected> FromSchema(JsonObject schema) =>
        (schema["fields"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().Select(f => new Expected(
            f["name"]?.GetValue<string>() ?? "", f["type"]?.GetValue<string>() ?? "string", f["servicenowType"]?.GetValue<string>() ?? "string",
            f["maxLength"] is JsonValue v && v.TryGetValue<int>(out var n) ? n : 0)).Where(e => e.Name.Length > 0).ToList();

    /// PURE. Every expected column, then the table's own columns SecurityInsight does not send, then the column mapping.
    public static IReadOnlyList<SchemaLine> Compare(IReadOnlyList<Expected> expected, IReadOnlyList<SnowColumn> actual, string? mapping, bool batchIdSent = true)
    {
        var lines = new List<SchemaLine>();
        var byName = actual.GroupBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        foreach (var e in expected)
        {
            // #912: u_si_batch_id is sent once a staging status table is set; until then a missing column is a to-do, not a loss
            if (!batchIdSent && !byName.ContainsKey(e.Name) && string.Equals(e.Name, ServiceNowStagingStatus.BatchIdColumn, StringComparison.OrdinalIgnoreCase))
            { lines.Add(new(e.Name, "missing", "amber", $"missing in the table -- not sent until the staging status table is set; create it as string, length {ServiceNowStagingStatus.BatchIdLength.ToString(CultureInfo.InvariantCulture)}, with the staging status table")); continue; }
            if (!byName.TryGetValue(e.Name, out var a)) { lines.Add(new(e.Name, "missing", "red", $"missing in the table: its values would be lost -- create it as {e.ServiceNowType}" + (e.ServiceNowType == "string" ? $", length {e.MaxLength.ToString(CultureInfo.InvariantCulture)}" : ""))); continue; }
            var type = (a.Type ?? "").Trim().ToLowerInvariant();
            var problems = new List<SchemaLine>();
            if (IsText(type) && a.MaxLength > 0 && e.MaxLength > a.MaxLength)
                problems.Add(new(e.Name, "short", "red", $"too short: it holds {a.MaxLength.ToString(CultureInfo.InvariantCulture)} characters, SecurityInsight sends up to {e.MaxLength.ToString(CultureInfo.InvariantCulture)} -- longer values would be cut. Make it {e.MaxLength.ToString(CultureInfo.InvariantCulture)} long."));
            var accepts = Accepts.TryGetValue(e.ServiceNowType, out var ok) ? ok : [e.ServiceNowType];
            if (type.Length > 0 && !accepts.Contains(type, StringComparer.OrdinalIgnoreCase))
                problems.Add(new(e.Name, "type", "amber", $"type {type}, SecurityInsight sends {e.Type} ({e.ServiceNowType}) -- the value arrives as text the transform map has to convert"));
            if (problems.Count == 0) lines.Add(new(e.Name, "ok", "ok", $"{(type.Length > 0 ? type : "type not read")}{(a.MaxLength > 0 ? ", length " + a.MaxLength.ToString(CultureInfo.InvariantCulture) : "")}"));
            else lines.AddRange(problems);
        }
        var sent = expected.Select(e => e.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var a in actual.Where(a => !sent.Contains(a.Name) && !a.Name.StartsWith("sys_", StringComparison.OrdinalIgnoreCase)).OrderBy(a => a.Name, StringComparer.Ordinal))
            lines.Add(new(a.Name, "extra", "info", "a column of the table SecurityInsight does not send (fine)"));
        lines.Add((mapping ?? "").Trim().ToLowerInvariant() switch
        {
            "name" => new SchemaLine("", "mapping", "ok", "REST Insert Multiple matches the columns by name"),
            "label" => new SchemaLine("", "mapping", "red", "ServiceNow matches the columns by LABEL: rows land empty where a label is not the column's name -- add a REST Insert Multiple record for the table with Column mappings = Column name"),
            _ => new SchemaLine("", "mapping", "amber", "the REST Insert Multiple column mapping could not be read -- check it is Column name"),
        });
        return lines;
    }

    /// The worst level of the lines: red, amber or ok.
    public static string Worst(IReadOnlyList<SchemaLine> lines) => lines.Any(l => l.Level == "red") ? "red" : lines.Any(l => l.Level == "amber") ? "amber" : "ok";
}

/// One item of "What is needed": done (true), not yet (false), or not known here (null), with its words and a hint.
public sealed record ChecklistItem(string Key, bool? Done, string Text, string? Hint = null);

/// <summary>"WHAT IS NEEDED" for one ServiceNow connector (PURE): each item ticked from what the install actually has --
/// never a secret value, only its name and when it was set.</summary>
public static class ServiceNowChecklist
{
    /// The connector's items and one output's items (the page shows the connector's once, then each output's).
    public static IReadOnlyList<ChecklistItem> Build(ConnectorRow? c, ServiceNowOutputs.Info info, string? table, SecretStateView? keyState, SnowCheckRow? latest,
        IReadOnlyDictionary<string, SecretStateView?>? states = null) =>
        BuildConnector(c, keyState, latest, states).Concat(BuildOutput(info, table, latest)).ToList();

    /// The ServiceNow team's part per output: the Import Set table, its column mapping, the transform map.
    public static IReadOnlyList<ChecklistItem> BuildOutput(ServiceNowOutputs.Info info, string? table, SnowCheckRow? latest)
    {
        var f = latest?.Facts;
        var items = new List<ChecklistItem>();
        // 4. the Import Set table
        items.Add(string.IsNullOrWhiteSpace(table)
            ? new("table", false, $"Import Set table: not set (the setting {info.TableSetting}).", "Agree the name with the ServiceNow team (for example u_si_ci_import), create it from the ServiceNow schema (JSON) and set it on Settings.")
            : new("table", f?.TableExists, $"Import Set table: {table.Trim()} (the setting {info.TableSetting})" + (f?.TableExists == false ? " -- it does not exist on the instance yet." : "."),
                "Created from the ServiceNow schema (JSON): every column with its type and length."));

        // 5. the column mapping
        items.Add(new("mapping", f is null || f.Mapping.Length == 0 ? (bool?)null : f.Mapping == "name",
            "REST Insert Multiple for the table with Column mappings = Column name (by default ServiceNow matches by label, and every column lands empty).",
            f is null || f.Mapping.Length == 0 ? "Verify reads it." : f.MappingText));

        // 6. the transform map -- the ServiceNow team's own, never read from here
        items.Add(new("transform", null, "A transform map from the Import Set table to " + (ServiceNowTeamPack.TargetOf(info.Output)?.Intended ?? "its target") + ", built by your ServiceNow team (the team pack has the how-to).",
            "SecurityInsight does not read transform maps; the first run's import set shows whether rows were transformed."));
        return items;
    }

    /// The connector's items: the instance, how it signs in (an API key OR a user and a password), the roles.
    /// <paramref name="states"/>: the Set value state of each secret reference (apikey, user, password).
    public static IReadOnlyList<ChecklistItem> BuildConnector(ConnectorRow? c, SecretStateView? keyState, SnowCheckRow? latest, IReadOnlyDictionary<string, SecretStateView?>? states = null)
    {
        var settings = Obj(c?.SettingsJson); var refs = Obj(c?.SecretRefsJson);
        string? Str(JsonObject o, string k) => o.FirstOrDefault(p => string.Equals(p.Key, k, StringComparison.OrdinalIgnoreCase)).Value is JsonValue v && v.TryGetValue<string>(out var s) && s.Trim().Length > 0 ? s.Trim() : null;
        var items = new List<ChecklistItem>();
        var f = latest?.Facts;
        SecretStateView? StateOf(string r) => states is not null && states.TryGetValue(r, out var s) ? s : r == "apikey" ? keyState : null;
        keyState = StateOf("apikey");

        // 1. the instance
        var inst = Str(settings, "instance"); var instRef = Str(refs, "instance");
        items.Add(instRef is not null
            ? new("instance", true, $"Instance address: read from the Key Vault secret {instRef}.", "Set it on this page instead to see and change it here (remove the 'instance' secret reference).")
            : inst is not null ? new("instance", ServiceNowInstanceUrl.Validate(inst).Problem is null, $"Instance address: {inst}", ServiceNowInstanceUrl.Validate(inst).Problem)
            : new("instance", false, "Instance address: not set.", "Enter it below, for example " + ServiceNowInstanceUrl.Example + "."));

        // 2. how it signs in (#903): an API key OR a user and a password -- a wrong combination said in plain words, and a 401
        //    with an API key says the likely cause (a password stored as an API key)
        var key = Str(refs, "apikey"); var user = Str(refs, "user"); var pw = Str(refs, "password");
        var refused = f?.ConnectionKind == "auth";
        if (ServiceNowCredential.Problem(c?.SecretRefsJson) is { } wrong)
            items.Add(new("key", false, "How SecurityInsight signs in: " + wrong + ".", "Choose one way below; the other's references are removed (no Key Vault secret is deleted)."));
        else if (key is not null)
            items.Add(refused ? new("key", false, $"API key: {key} -- ServiceNow refused it (401) on the last check.", ApiKeyRefusedHint)
                : keyState?.State switch
                {
                    SecretState.Stored => new("key", true, $"API key: stored in your Key Vault as {key}. {keyState.Text}"),
                    SecretState.Waiting => new("key", null, $"API key: {key} -- {keyState.Text}"),
                    SecretState.Failed => new("key", false, $"API key: {key} -- {keyState.Text}"),
                    _ when f?.ConnectionOk == true => new("key", true, $"API key: {key} is in your Key Vault (the last check signed in with it)."),
                    _ => new("key", null, $"API key: the connector names the Key Vault secret {key}; it was not set from this page.", "A SuperAdmin pastes it below (Set value); Verify then signs in with it."),
                });
        else if (user is not null && pw is not null)
        {
            var us = StateOf("user"); var ps = StateOf("password");
            bool? done = refused ? false
                : f?.ConnectionOk == true || (us?.State == SecretState.Stored && ps?.State == SecretState.Stored) ? true
                : us?.State == SecretState.Failed || ps?.State == SecretState.Failed ? false : null;
            items.Add(new("key", done, $"Integration user: the Key Vault secrets {user} and {pw}." + (refused ? " ServiceNow refused them (401) on the last check." : ""),
                refused ? "The user name or the password is wrong, has expired, or the user may not use the REST API. Set both again below." : done == true ? null : "A SuperAdmin pastes the user name and the password below (Set value); Verify then signs in with them."));
        }
        else items.Add(new("key", false, "How SecurityInsight signs in: not chosen yet -- an API key, or a user and a password.", "Choose below what your ServiceNow team gave you, stage it, then set its value."));

        // 3. the roles
        var roles = string.Join("; ", ServiceNowOutputs.Roles.Select(r => string.Join(" and ", r.Roles) + " (" + r.Why + ")"));
        bool? rolesOk = f is null || latest is null ? (bool?)null
            : f.ConnectionKind == "role" || f.Role.Length > 0 ? false
            : f.ConnectionOk == true && f.ColumnsRead && f.Mapping is "name" or "label" ? true : null;
        items.Add(new("roles", rolesOk, "The ServiceNow user SecurityInsight signs in with (or the API key's user) has the roles: " + roles + ".",
            rolesOk == false ? "The last check was refused: " + (f!.Role.Length > 0 ? "missing " + f.Role : f.ConnectionText) : rolesOk is null ? "Verify tells whether the reads are allowed; the send role shows on the first run." : null));
        return items;
    }

    /// The hint for a 401 with an API key -- the customer case this was built for.
    public const string ApiKeyRefusedHint = "If what your ServiceNow team gave you is a user name and a password, choose 'A user and a password' below and set both there -- a password stored as an API key is refused by ServiceNow (401). Otherwise the key is wrong, has expired, or is not allowed for the REST API: set it again.";

    private static JsonObject Obj(string? json)
    {
        try { return JsonNode.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json) as JsonObject ?? new JsonObject(); }
        catch (JsonException) { return new JsonObject(); }
    }
}

/// <summary>
/// "VERIFY": starts the mail job once with SI_SNOW_VERIFY=&lt;output&gt; (and the outbox-only switch, so nothing else is sent),
/// which runs the ServiceNow checks with the engine identity and records the result -- the web app never reads the key.
/// The same pattern as the mail restriction's Verify (<see cref="MailVerifier"/>).
/// </summary>
public sealed class ServiceNowVerifier(IJobsClient jobs, IOptions<JobsOptions> options, ILogger<ServiceNowVerifier> log)
{
    public const string VerifyEnv = "SI_SNOW_VERIFY";
    public const string ByEnv = "SI_SNOW_VERIFY_BY";
    /// Both ServiceNow outputs at once.
    public const string AllOutputs = "all";

    public async Task<(bool Started, string Message)> StartAsync(string output, string by, CancellationToken ct)
    {
        // #903: "all" = both outputs of the one data-out connector (the mail job's Invoke-SISnowChecks -Only all)
        if (output != AllOutputs && ServiceNowOutputs.Of(output) is null) return (false, "Not started: that is not a ServiceNow output.");
        var job = options.Value.CloseLoopMailJob;
        if (!jobs.IsConfigured || string.IsNullOrWhiteSpace(job))
            return (false, "The check cannot be started from here on this install -- it runs before the next run of the output and every day.");
        try
        {
            await jobs.StartWithEnvAsync(job, new Dictionary<string, string>
            {
                [SI.Management.Web.Exemptions.OutboxExemptionMailer.OnlyEnv] = "1", [VerifyEnv] = output, [ByEnv] = (by ?? "").Length > 200 ? by![..200] : by ?? "",
            }, ct);
            return (true, "The check was started: SecurityInsight signs in to ServiceNow with the stored key and reads the table -- reload this page in a few minutes to see the result.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the mail job could not be started for a ServiceNow check");
            return (false, "The check could not be started: " + ex.Message);
        }
    }
}

/// <summary>
/// "N ROWS WOULD BE SENT" of a ServiceNow output, from stored data: the vulnerable items by the scope's count (the indexed
/// columns of the published run's findings, <see cref="SI.Management.Web.Reports.IReportStore.ScopeCountAsync"/>), the CIs by
/// one count of the CI table with the output's own filter on the CI's class. A filter the count cannot apply says so --
/// the export applies it row by row.
/// </summary>
public sealed class ServiceNowRowCount(ISqlExecutor sql)
{
    public const string CiCountSql = """
IF OBJECT_ID(N'sidata.Ci') IS NULL
    SELECT CAST(0 AS bigint) AS N, CAST(0 AS bigint) AS Total;
ELSE
    SELECT COUNT_BIG(CASE WHEN @Classes IS NULL OR c.Class IN (SELECT [value] FROM OPENJSON(@Classes)) THEN 1 END) AS N, COUNT_BIG(*) AS Total
    FROM sidata.Ci AS c WHERE c.DocJson IS NOT NULL;
""";

    /// PURE. The classes of the output's filter when it filters on the CI's class only (null = no filter); Countable false =
    /// the filter names another field (the export applies it).
    public static (bool Countable, string? ClassesJson) Classes(JsonObject? filter)
    {
        if (filter is null || filter.Count == 0) return (true, null);
        if (filter.Count != 1 || !filter.ContainsKey("si_class")) return (false, null);
        var vals = filter["si_class"] is JsonArray a ? a.Select(x => OutputMapper.Text(x)).ToList() : [OutputMapper.Text(filter["si_class"])];
        return (true, JsonSerializer.Serialize(vals));
    }

    /// (rows that would be sent, of how many CIs) -- null when the filter cannot be counted here.
    public async Task<(long? N, long Total)> CiAsync(JsonObject? filter, CancellationToken ct)
    {
        var (countable, classes) = Classes(filter);
        var r = (await sql.QueryAsync(CiCountSql, new Dictionary<string, object?> { ["Classes"] = classes }, ct)).FirstOrDefault();
        var total = r?.Long("Total") ?? 0;
        return (countable ? (long?)(r?.Long("N") ?? 0) : null, total);
    }
}
