using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using SI.Management.Web.Changes;

namespace SI.Management.Web.GetStarted;

/// <summary>
/// Get Started's connectors step as a FORM in the step (#446: "show options in the wizard, dont link to things"): what a
/// first setup needs -- ServiceNow (vulnerabilities or CMDB) or the SQL CMDB hand-off database, its connection fields,
/// switch it on, the mode -- turned into the SAME <see cref="ConnectorWrite"/> the Connector setup page stages, so it is
/// checked by <see cref="ConnectorRepository.Validate"/> and written by the connector repository (the page does the write)
/// (cfg.Connector + its cfg.ChangeLog row + the RowVersion check). Everything the step does not show (a rest mapping,
/// other settings keys, the create / close switches) is kept as it is. PURE: no SQL here.
/// </summary>
public static class GetStartedConnector
{
    public const string Prefix = "cx:";
    /// The version each shown connector had when the step was opened: cxver:&lt;name&gt;.
    public const string VersionPrefix = "cxver:";
    /// "Save and run once" of one card posts __action = runconnector:&lt;slot&gt;.
    public const string RunAction = "runconnector:";

    /// <summary>
    /// ONE CARD PER CONNECTOR (owner 2026-10-20 on Get Started step 10: "this page is wrong, as it is either-or - default
    /// sql is on for pro. and technically i can choose to enable both cmdb and vulnerability in servicenow - it is not
    /// either-or"): every connector the step sets up, each with its own state, fields, switch, mode and Run once -- any
    /// combination can be on at once. The ServiceNow instance and its secret names are entered once and shared by both
    /// ServiceNow connectors.
    /// </summary>
    public sealed record Slot(string Key, string Kind, string Direction, string Title, string What, bool OnInPro);

    public static readonly IReadOnlyList<Slot> Slots =
    [
        new("sqlvuln", "sql", "vulnerability", "SQL vulnerability target",
            "The vulnerability close-loop opens, closes and reopens SecurityInsight's vulnerabilities in a SQL table your other tools read.", true),
        new("sqlcmdb", "sql", "cmdb", "SQL CMDB hand-off",
            "The CIs written to a SQL hand-off database that ServiceNow (or another CMDB) imports.", false),
        new("snowvuln", "servicenow", "vulnerability", "ServiceNow vulnerabilities",
            "The vulnerability close-loop: vulnerable items opened, closed and reopened in ServiceNow's vulnerable-item table. (The Import Set data out -- CIs and vulnerable items -- sends through the ServiceNow data-out connector, Connectors > Setup.)", false),
        new("snowcmdb", "servicenow", "cmdb", "ServiceNow CMDB",
            "The ServiceNow CMDB job: configuration items planned and enriched in ServiceNow's CMDB. (The Import Set data out sends through the ServiceNow data-out connector, Connectors > Setup.)", false),
    ];

    public static Slot? SlotOf(string? key) => Slots.FirstOrDefault(s => s.Key == key);

    /// A card's field name.
    public static string Field(Slot s, string name) => Prefix + s.Key + ":" + name;

    /// The connector a first setup creates for a card (an existing connector of the same kind and direction is edited instead).
    public static string DefaultName(string kind, string direction) =>
        kind == "sql" ? (direction == "vulnerability" ? "vulnerability-sql" : "sql-cmdb") : direction == "cmdb" ? "servicenow-cmdb" : "servicenow-vulnerabilities";

    /// The job that runs a connector -- what "Run once" starts (the Jobs page's Run now on that job).
    public static string JobKey(string kind, string direction) =>
        kind == "sql" ? (direction == "vulnerability" ? "asset-vulnerabilities" : "asset-cmdb-sql") : direction == "cmdb" ? "asset-cmdb" : "asset-vulns-servicenow";

    /// The connectors this step sets up (ServiceNow and SQL, either direction).
    public static bool Covers(ConnectorRow r) => r.Kind is "servicenow" or "sql";

    /// What one card holds. Secret fields are Key Vault secret NAMES (shared by the ServiceNow cards).
    public sealed record Form(string? Kind, string? Direction, string? Table, string? InstanceRef, string? UserRef, string? PasswordRef,
        string? Server, string? Database, bool Enabled, string Mode)
    {
        public string Dir => Direction is "cmdb" ? "cmdb" : Kind == "sql" && Direction is null ? "cmdb" : "vulnerability";
    }

    private static string? T(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// One card as posted (the ServiceNow secret names from the shared fields).
    public static Form Read(IFormCollection f, Slot s) => new(
        s.Kind, s.Direction, T(f[Field(s, "Table")]),
        s.Kind == "servicenow" ? T(f[Prefix + "InstanceRef"]) : null, s.Kind == "servicenow" ? T(f[Prefix + "UserRef"]) : null, s.Kind == "servicenow" ? T(f[Prefix + "PasswordRef"]) : null,
        T(f[Field(s, "Server")]), T(f[Field(s, "Database")]),
        f[Field(s, "Enabled")].Any(v => v == "true"), T(f[Field(s, "Mode")])?.ToLowerInvariant() ?? "whatif");

    /// Every card as posted.
    public static IReadOnlyDictionary<string, Form> ReadAll(IFormCollection f) => Slots.ToDictionary(s => s.Key, s => Read(f, s), StringComparer.Ordinal);

    /// The card a connector row belongs to.
    public static Slot? SlotFor(ConnectorRow r) => Slots.FirstOrDefault(s => s.Kind == r.Kind && s.Direction == r.Direction);

    /// A card's title for a kind and direction (the connector's name when no card shows it).
    public static string TitleOf(string kind, string direction, string name) => Slots.FirstOrDefault(s => s.Kind == kind && s.Direction == direction)?.Title ?? name;

    /// A card with nothing of its own filled in and not switched on (the shared ServiceNow secret names do not count -- they
    /// alone never create a connector): nothing to save for it.
    public static bool IsEmpty(Form f) =>
        f.Kind is null || (!f.Enabled && new[] { f.Table, f.Server, f.Database }.All(v => v is null));

    /// The connector the step opens with: an enabled one first, else the first one it covers.
    public static ConnectorRow? Shown(IReadOnlyList<ConnectorRow> rows) =>
        rows.Where(Covers).OrderByDescending(r => r.Enabled).ThenBy(r => r.Name, StringComparer.Ordinal).FirstOrDefault();

    /// The existing connector a choice edits: the shown one when it matches, else the first of that kind and direction.
    public static ConnectorRow? Match(IReadOnlyList<ConnectorRow> rows, string kind, string direction) =>
        rows.Where(r => r.Kind == kind && r.Direction == direction).OrderByDescending(r => r.Enabled).ThenBy(r => r.Name, StringComparer.Ordinal).FirstOrDefault();

    /// One card as the step opens: its connector's values (none = empty, switched off, whatif); the ServiceNow secret names
    /// from any ServiceNow connector (they are shared).
    public static Form Prefill(IReadOnlyList<ConnectorRow> rows, Slot s)
    {
        var cur = Match(rows, s.Kind, s.Direction);
        var snow = rows.Where(r => r.Kind == "servicenow").OrderByDescending(r => r.Enabled).ThenBy(r => r.Name, StringComparer.Ordinal).FirstOrDefault();
        return new Form(s.Kind, s.Direction, Get(cur?.SettingsJson, "table"),
            Get(snow?.SecretRefsJson, "instance"), Get(snow?.SecretRefsJson, "user"), Get(snow?.SecretRefsJson, "password"),
            Get(cur?.SettingsJson, "server"), Get(cur?.SettingsJson, "database"), cur?.Enabled ?? false,
            // #865: the own SQL vulnerability target shows as it saves -- apply
            ConnectorRepository.IsOwnSqlTarget(s.Kind, s.Direction) ? "apply" : cur?.Mode ?? "whatif");
    }

    /// Every card as the step opens.
    public static IReadOnlyDictionary<string, Form> PrefillAll(IReadOnlyList<ConnectorRow> rows) => Slots.ToDictionary(s => s.Key, s => Prefill(rows, s), StringComparer.Ordinal);

    private static JsonObject Obj(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new JsonObject();
        try { return JsonNode.Parse(json) as JsonObject ?? new JsonObject(); }
        catch (JsonException) { return new JsonObject(); }
    }

    public static string? Get(string? json, string key)
    {
        foreach (var p in Obj(json)) if (p.Key.Equals(key, StringComparison.OrdinalIgnoreCase)) return p.Value is JsonValue v && v.TryGetValue<string>(out var s) ? s : p.Value?.ToString();
        return null;
    }

    /// Sets (or, for null, removes) one key -- an existing key keeps its spelling and its place.
    private static void Put(JsonObject o, string key, string? value)
    {
        var have = o.Select(p => p.Key).Where(k => k.Equals(key, StringComparison.OrdinalIgnoreCase)).ToList();
        if (value is null) { foreach (var k in have) o.Remove(k); return; }
        foreach (var k in have.Skip(1)) o.Remove(k);
        o[have.Count > 0 ? have[0] : key] = value;
    }

    private static string? Text(JsonObject o) => o.Count == 0 ? null : o.ToJsonString();

    /// <summary>
    /// The write the step makes: the chosen kind and direction on the connector it edits (<paramref name="current"/>, or a
    /// new one named <see cref="DefaultName"/>), with the step's fields merged into its settings / secret references and
    /// everything else kept. <paramref name="expectedVersion"/> is the version the step showed (null = it did not exist).
    /// </summary>
    public static ConnectorWrite Build(Form f, ConnectorRow? current, long? expectedVersion)
    {
        var kind = f.Kind ?? "";
        var dir = f.Dir;
        var settings = Obj(current?.SettingsJson);
        var refs = Obj(current?.SecretRefsJson);
        if (kind == "sql")
        {
            Put(settings, "server", f.Server);
            Put(settings, "database", f.Database);
        }
        else
        {
            if (dir == "vulnerability") Put(settings, "table", f.Table);
            Put(refs, "instance", f.InstanceRef);
            Put(refs, "user", f.UserRef);
            Put(refs, "password", f.PasswordRef);
        }
        // #865: the own SQL vulnerability target is always apply + create + close (ConnectorRepository.AlwaysOn)
        return ConnectorRepository.AlwaysOn(new ConnectorWrite(current?.Name ?? DefaultName(kind, dir), "Set", kind, dir, f.Enabled, f.Mode,
            current?.AllowCreate ?? true, current?.AllowClose ?? false, Text(settings), Text(refs), current?.MappingJson, expectedVersion,
            "Get Started: connectors"));
    }

    private static string? Norm(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Object) return JsonSerializer.Serialize(d.RootElement);
            // the order of the keys is no change
            var props = d.RootElement.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Name) + ":" + JsonSerializer.Serialize(p.Value)).ToList();
            return props.Count == 0 ? null : "{" + string.Join(",", props) + "}";
        }
        catch (JsonException) { return json.Trim(); }
    }

    /// The write changes nothing the connector already has: Save &amp; next writes no row and no change log.
    public static bool Unchanged(ConnectorWrite w, ConnectorRow? current) =>
        current is not null && w.Kind == current.Kind && w.Direction == current.Direction && w.Enabled == current.Enabled && w.Mode == current.Mode
        && Norm(w.SettingsJson) == Norm(current.SettingsJson) && Norm(w.SecretRefsJson) == Norm(current.SecretRefsJson);
}
