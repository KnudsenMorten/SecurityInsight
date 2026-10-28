using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

public sealed record ConnectorRow(long ConnectorId, string Name, string Kind, string Direction, bool Enabled, string Mode, bool AllowCreate, bool AllowClose,
    string? SettingsJson, string? SecretRefsJson, string? MappingJson, DateTime? UpdatedAt, string? UpdatedBy, long Version);

public sealed record ConnectorRunRow(string ConnectorName, string Kind, string RunId, DateTime? StartedAt, DateTime? EndedAt, string Mode, string Outcome,
    long PlanOpen, long PlanReopen, long PlanUpdate, long PlanClose, long Held, long Opened, long Reopened, long Updated, long Closed, long Errors, long NotSent,
    string? HaltReason, string? Error);

/// One connector change: Set (create / replace by Name) or Reset (remove). ExpectedVersion = the row's RowVersion when it
/// was read (null = it did not exist then); a write is refused when the row moved on since.
public sealed record ConnectorWrite(string Name, string Action, string Kind, string Direction, bool Enabled, string Mode, bool AllowCreate, bool AllowClose,
    string? SettingsJson, string? SecretRefsJson, string? MappingJson, long? ExpectedVersion, string? Reason);

/// <summary>
/// THE one class that reads and writes cfg.Connector / cfg.ConnectorRun (sql\si-pro-settings.sql, phase E) -- the C# twin of
/// Set-SIConnector / ConvertFrom-SIConnectorRow (engine\asset-cmdb\_shared\SI-Connector.ps1). Validated FIRST by the same
/// rules the close-loop applies at run time (nothing is sent for a refused connector), then ONE batch, ONE transaction
/// with its cfg.ChangeLog row (Name 'connector/&lt;name&gt;', Scope 'connector', Kind 'connector') and an optimistic
/// RowVersion check. A secret's VALUE is refused everywhere: secret references are Key Vault secret NAMES.
/// </summary>
public sealed partial class ConnectorRepository
{
    public static readonly IReadOnlyList<string> Kinds = ["sql", "servicenow", "rest"];
    /// #903: 'data-out' = the ServiceNow connector both ServiceNow Import Set outputs send through (<see cref="ServiceNowDataOut"/>).
    public static readonly IReadOnlyList<string> Directions = ["vulnerability", "cmdb", ServiceNowDataOut.Direction];
    /// The kinds that may have the cmdb direction: the ServiceNow CMDB connector, and the SQL CMDB hand-off database that
    /// ServiceNow imports itself (engine/asset-cmdb/_shared/SI-CmdbSqlConnector.ps1).
    public static readonly IReadOnlyList<string> CmdbKinds = ["servicenow", "sql"];
    public static readonly IReadOnlyList<string> Modes = ["whatif", "apply"];

    /// <summary>
    /// #865 (owner 2026-10-21: "for the sql it should be on always"): the SQL vulnerability target (kind sql, direction
    /// vulnerability -- `vulnerability-sql`) is SecurityInsight's OWN record of every vulnerability's lifecycle, the source of
    /// Changes &amp; trends &gt; Vulnerabilities over time / per collection. In test mode it records nothing, so it is never in
    /// test mode: every write of it is apply with create and close on (<see cref="AlwaysOn"/>), and the pages do not offer
    /// whatif for it. A connector to a customer system (servicenow, rest, the sql CMDB hand-off) keeps its own mode.
    /// </summary>
    public static bool IsOwnSqlTarget(string? kind, string? direction) => kind == "sql" && (direction ?? "vulnerability") == "vulnerability";

    public static string OwnSqlTargetNote => "SecurityInsight's own SQL vulnerability target is always on (apply, create and close): it is SecurityInsight's record of every vulnerability's lifecycle and the source of " + SI.Management.Web.Navigation.NavModel.PathOf("/Management/Closure") + " and " + SI.Management.Web.Navigation.NavModel.PathOf("/Collection/Lifecycle") + ". Test mode would record nothing, so it is not offered.";

    /// The write as it is saved: the own SQL target always apply + create + close; #903 a ServiceNow data-out connector always
    /// apply (data out has no test mode; create / close mean nothing to it); every other connector unchanged.
    public static ConnectorWrite AlwaysOn(ConnectorWrite w) =>
        w.Action != "Set" ? w
        : IsOwnSqlTarget(w.Kind, w.Direction) ? w with { Mode = "apply", AllowCreate = true, AllowClose = true }
        : ServiceNowDataOut.Is(w.Kind, w.Direction) ? w with { Mode = "apply", AllowCreate = false, AllowClose = false }
        : w;
    public static readonly IReadOnlyList<string> Operations = ["listOpen", "create", "update", "close", "reopen"];
    public static readonly IReadOnlyList<string> AuthTypes = ["none", "bearer", "basic", "oauth-client-credentials", "apikey-header"];
    public static readonly IReadOnlyList<string> Tokens = ["asset.id", "asset.name", "asset.ciId", "vuln.cve", "vuln.severity", "vuln.riskScore", "vuln.state",
        "vuln.closeReason", "vuln.firstSeen", "vuln.lastSeen", "finding.id", "external.id", "reason", "now", "connector.name", "source", "baseUrl"];

    [GeneratedRegex(@"^[a-z0-9][a-z0-9\-]{1,62}$", RegexOptions.CultureInvariant)] public static partial Regex NamePattern();
    [GeneratedRegex(@"^[A-Za-z0-9\-]{1,127}$", RegexOptions.CultureInvariant)] private static partial Regex SecretNameChars();
    [GeneratedRegex(@"(?i)(password|passwd|secret|token|apikey|api_key|api-key|credential|bearer|privatekey)", RegexOptions.CultureInvariant)] private static partial Regex SecretKey();
    [GeneratedRegex(@"(?i)Ref$|^tokenUrl$|^idPath$|^itemsPath$|^nextLinkPath$|^totalPath$", RegexOptions.CultureInvariant)] private static partial Regex NotASecretKey();
    [GeneratedRegex(@"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}", RegexOptions.CultureInvariant)] private static partial Regex Token();
    [GeneratedRegex(@"^settings\.([A-Za-z0-9_\-]+)$", RegexOptions.CultureInvariant)] private static partial Regex SettingToken();

    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.Connector') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    public const string ListSql = """
IF OBJECT_ID(N'cfg.Connector') IS NOT NULL
SELECT ConnectorId, Name, Kind, Direction, CONVERT(int, Enabled) AS Enabled, Mode, CONVERT(int, AllowCreate) AS AllowCreate, CONVERT(int, AllowClose) AS AllowClose,
       SettingsJson, SecretRefsJson, MappingJson, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version
FROM cfg.Connector
ORDER BY Name;
""";

    public const string ReadSql = """
SELECT ConnectorId, Name, Kind, Direction, CONVERT(int, Enabled) AS Enabled, Mode, CONVERT(int, AllowCreate) AS AllowCreate, CONVERT(int, AllowClose) AS AllowClose,
       SettingsJson, SecretRefsJson, MappingJson, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version
FROM cfg.Connector
WHERE Name = @Name;
""";

    /// The newest runs, all connectors or one (@Name NULL = all). Without the table: no rows, not an error.
    public const string RunsSql = """
IF OBJECT_ID(N'cfg.ConnectorRun') IS NOT NULL
SELECT TOP (@Top) ConnectorName, Kind, RunId, StartedAt, EndedAt, Mode, Outcome, PlanOpen, PlanReopen, PlanUpdate, PlanClose, Held,
       Opened, Reopened, Updated, Closed, Errors, NotSent, HaltReason, Error
FROM cfg.ConnectorRun
WHERE (@Name IS NULL OR ConnectorName = @Name)
ORDER BY StartedAt DESC, ConnectorRunId DESC;
""";

    public const string WriteSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.Connector') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @cur bigint = NULL, @old nvarchar(max) = NULL;
SELECT @cur = CONVERT(bigint, c.RowVersion),
       @old = (SELECT c.Name, c.Kind, c.Direction, c.Enabled, c.Mode, c.AllowCreate, c.AllowClose, c.SettingsJson, c.SecretRefsJson, c.MappingJson FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM cfg.Connector c WITH (UPDLOCK, HOLDLOCK) WHERE c.Name = @Name;
IF (@Expected IS NULL AND @cur IS NOT NULL) OR (@Expected IS NOT NULL AND (@cur IS NULL OR @cur <> @Expected))
BEGIN
    COMMIT;
    SELECT N'Stale' AS Outcome;
    RETURN;
END;
IF @Action = N'Reset'
    DELETE FROM cfg.Connector WHERE Name = @Name;
ELSE IF @cur IS NOT NULL
    UPDATE cfg.Connector SET Kind = @Kind, Direction = @Direction, Enabled = @Enabled, Mode = @Mode, AllowCreate = @AllowCreate, AllowClose = @AllowClose,
           SettingsJson = @SettingsJson, SecretRefsJson = @SecretRefsJson, MappingJson = @MappingJson, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
    WHERE Name = @Name;
ELSE
    INSERT cfg.Connector (Name, Kind, Direction, Enabled, Mode, AllowCreate, AllowClose, SettingsJson, SecretRefsJson, MappingJson, CreatedBy, UpdatedBy)
    VALUES (@Name, @Kind, @Direction, @Enabled, @Mode, @AllowCreate, @AllowClose, @SettingsJson, @SecretRefsJson, @MappingJson, @By, @By);
-- #903: at most ONE ServiceNow data-out connector is switched on -- a second is refused and nothing is written
IF (SELECT COUNT(*) FROM cfg.Connector WHERE LOWER(Kind) = N'servicenow' AND LOWER(Direction) = N'data-out' AND Enabled = 1) > 1
BEGIN
    ROLLBACK;
    SELECT N'Conflict' AS Outcome;
    RETURN;
END;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'connector/' + @Name, N'connector', N'connector', @Action, @old, @New, @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string MissingTableMessage = "this database has no cfg.Connector table yet -- run the Pro settings schema (sql\\si-pro-settings.sql) first";

    private readonly ISqlExecutor _sql;
    public ConnectorRepository(ISqlExecutor sql) => _sql = sql;

    private static bool Bit(SqlRow r, string c) => (r.Long(c) ?? 0) != 0;

    private static ConnectorRow Map(SqlRow r) => new(r.Long("ConnectorId") ?? 0, r.Str("Name") ?? "", r.Str("Kind") ?? "", r.Str("Direction") ?? "vulnerability",
        Bit(r, "Enabled"), r.Str("Mode") ?? "whatif", Bit(r, "AllowCreate"), Bit(r, "AllowClose"), r.Str("SettingsJson"), r.Str("SecretRefsJson"), r.Str("MappingJson"),
        r.Date("UpdatedAt"), r.Str("UpdatedBy"), r.Long("Version") ?? 0);

    private static ConnectorRunRow MapRun(SqlRow r) => new(r.Str("ConnectorName") ?? "", r.Str("Kind") ?? "", r.Str("RunId") ?? "", r.Date("StartedAt"), r.Date("EndedAt"),
        r.Str("Mode") ?? "", r.Str("Outcome") ?? "", r.Long("PlanOpen") ?? 0, r.Long("PlanReopen") ?? 0, r.Long("PlanUpdate") ?? 0, r.Long("PlanClose") ?? 0, r.Long("Held") ?? 0,
        r.Long("Opened") ?? 0, r.Long("Reopened") ?? 0, r.Long("Updated") ?? 0, r.Long("Closed") ?? 0, r.Long("Errors") ?? 0, r.Long("NotSent") ?? 0, r.Str("HaltReason"), r.Str("Error"));

    public async Task<bool> TableExistsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("HasTable") == 1;

    public async Task<IReadOnlyList<ConnectorRow>> ListAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct)).Select(Map).ToList();

    public async Task<ConnectorRow?> ReadAsync(string name, CancellationToken ct) =>
        (await _sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["Name"] = name }, ct)).Select(Map).FirstOrDefault();

    public async Task<IReadOnlyList<ConnectorRunRow>> RunsAsync(string? name, int top, CancellationToken ct) =>
        (await _sql.QueryAsync(RunsSql, new Dictionary<string, object?> { ["Name"] = name, ["Top"] = Math.Clamp(top, 1, 500) }, ct)).Select(MapRun).ToList();

    public static ConnectorWrite FromRow(ConnectorRow r, string action, string? reason) =>
        new(r.Name, action, r.Kind, r.Direction, r.Enabled, r.Mode, r.AllowCreate, r.AllowClose, r.SettingsJson, r.SecretRefsJson, r.MappingJson, r.Version, reason);

    // ------------------------------------------------------------------------------------------------ validation

    /// PURE. Is this a Key Vault secret NAME (and not a secret pasted where a name belongs)? Same rule as Test-SIConnectorSecretName.
    public static bool IsSecretName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || !SecretNameChars().IsMatch(name)) return false;
        if (name.StartsWith("eyJ", StringComparison.Ordinal)) return false;
        if (!name.Contains('-') && name.Length >= 24 && name.Any(char.IsDigit) && name.Any(char.IsLetter)) return false;
        return true;
    }

    private static (JsonElement? Value, string? Error) Parse(string? text, string what)
    {
        if (string.IsNullOrWhiteSpace(text)) return (null, null);
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return (null, $"{what} must be a JSON object");
            return (doc.RootElement.Clone(), null);
        }
        catch (JsonException ex) { return (null, $"{what} is not valid JSON: {ex.Message}"); }
    }

    private static string? Str(JsonElement? o, string name)
    {
        if (o is not { ValueKind: JsonValueKind.Object } e) return null;
        foreach (var p in e.EnumerateObject()) if (p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) return p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.ToString();
        return null;
    }

    private static JsonElement? Prop(JsonElement? o, string name)
    {
        if (o is not { ValueKind: JsonValueKind.Object } e) return null;
        foreach (var p in e.EnumerateObject()) if (p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) return p.Value;
        return null;
    }

    private static IEnumerable<string> Keys(JsonElement? o) =>
        o is { ValueKind: JsonValueKind.Object } e ? e.EnumerateObject().Select(p => p.Name).ToList() : Enumerable.Empty<string>();

    /// Paths holding a secret-looking VALUE (a key named like a secret that is not a *Ref, or a literal Authorization header).
    public static IReadOnlyList<string> LiteralSecrets(JsonElement? root, string prefix)
    {
        var hits = new List<string>();
        void Walk(JsonElement v, string path)
        {
            if (v.ValueKind == JsonValueKind.Array) { var i = 0; foreach (var x in v.EnumerateArray()) Walk(x, $"{path}[{i++}]"); return; }
            if (v.ValueKind != JsonValueKind.Object) return;
            foreach (var p in v.EnumerateObject())
            {
                var here = path.Length > 0 ? path + "." + p.Name : p.Name;
                var isString = p.Value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(p.Value.GetString());
                if (isString && !NotASecretKey().IsMatch(p.Name) && SecretKey().IsMatch(p.Name)) hits.Add(here);
                if (isString && p.Name.Equals("authorization", StringComparison.OrdinalIgnoreCase)) hits.Add(here);
                if (p.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array) Walk(p.Value, here);
            }
        }
        if (root is { } r) Walk(r, prefix);
        return hits;
    }

    /// Every {{token}} in a JSON value.
    public static IReadOnlyList<string> TemplateTokens(JsonElement? root)
    {
        var list = new List<string>();
        void Walk(JsonElement v)
        {
            switch (v.ValueKind)
            {
                case JsonValueKind.String: foreach (Match m in Token().Matches(v.GetString() ?? "")) list.Add(m.Groups[1].Value); break;
                case JsonValueKind.Object: foreach (var p in v.EnumerateObject()) Walk(p.Value); break;
                case JsonValueKind.Array: foreach (var x in v.EnumerateArray()) Walk(x); break;
            }
        }
        if (root is { } r) Walk(r);
        return list;
    }

    private static void Mapping(JsonElement? m, ISet<string> refs, ISet<string> settings, bool allowCreate, bool allowClose, List<string> why)
    {
        if (m is null) { why.Add("a rest connector needs a mapping"); return; }
        var baseUrl = Str(m, "baseUrl");
        if (string.IsNullOrWhiteSpace(baseUrl) || !baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) why.Add("mapping.baseUrl must be an https:// URL");
        var auth = Prop(m, "auth");
        var type = Str(auth, "type");
        if (string.IsNullOrWhiteSpace(type)) type = "none";
        if (!AuthTypes.Contains(type)) why.Add($"mapping.auth.type '{type}' is not one of {string.Join(", ", AuthTypes)}");
        void NeedRef(string field)
        {
            var r = Str(auth, field);
            if (string.IsNullOrWhiteSpace(r)) { why.Add($"mapping.auth.{field} is required for {type}: the name of a secret reference"); return; }
            if (!refs.Contains(r)) why.Add($"mapping.auth.{field} names '{r}', which is not a secret reference of this connector");
        }
        switch (type)
        {
            case "bearer": NeedRef("secretRef"); break;
            case "apikey-header": NeedRef("secretRef"); if (string.IsNullOrWhiteSpace(Str(auth, "header"))) why.Add("mapping.auth.header is required for apikey-header"); break;
            case "basic":
                NeedRef("passwordRef");
                if (string.IsNullOrWhiteSpace(Str(auth, "user")) && string.IsNullOrWhiteSpace(Str(auth, "userRef"))) why.Add("mapping.auth.user (or userRef) is required for basic");
                else if (!string.IsNullOrWhiteSpace(Str(auth, "userRef"))) NeedRef("userRef");
                break;
            case "oauth-client-credentials":
                NeedRef("clientSecretRef");
                if (!(Str(auth, "tokenUrl") ?? "").StartsWith("https://", StringComparison.OrdinalIgnoreCase)) why.Add("mapping.auth.tokenUrl must be an https:// URL");
                if (string.IsNullOrWhiteSpace(Str(auth, "clientId"))) why.Add("mapping.auth.clientId is required for oauth-client-credentials");
                break;
        }
        var ops = Prop(m, "operations");
        var opNames = Keys(ops).ToList();
        foreach (var k in opNames.Where(k => !Operations.Contains(k))) why.Add($"mapping.operations.{k} is not an operation ({string.Join(", ", Operations)})");
        if (allowCreate && !opNames.Contains("create")) why.Add("mapping.operations.create is required when AllowCreate is on");
        if (allowClose && !opNames.Contains("close")) why.Add("mapping.operations.close is required when AllowClose is on");
        foreach (var k in opNames)
        {
            var op = Prop(ops, k);
            if (!Regex.IsMatch(Str(op, "method") ?? "", "^(?i)(GET|POST|PUT|PATCH|DELETE)$")) why.Add($"mapping.operations.{k}.method must be GET, POST, PUT, PATCH or DELETE");
            var url = Str(op, "url");
            if (string.IsNullOrWhiteSpace(url)) why.Add($"mapping.operations.{k}.url is required");
            if (k is "create" or "listOpen" && string.IsNullOrWhiteSpace(Str(op, "idPath")))
                why.Add(k == "create" ? "mapping.operations.create.idPath is required: without the external id SecurityInsight cannot recognise the item it created" : "mapping.operations.listOpen.idPath is required");
            if (k == "listOpen" && Prop(op, "paging") is { } pg)
            {
                var pt = Str(pg, "type");
                if (pt is not ("nextLink" or "offset" or "none")) why.Add("mapping.operations.listOpen.paging.type must be nextLink, offset or none");
                if (pt == "nextLink" && string.IsNullOrWhiteSpace(Str(pg, "nextLinkPath"))) why.Add("mapping.operations.listOpen.paging.nextLinkPath is required for nextLink paging");
                if (pt == "offset" && (string.IsNullOrWhiteSpace(Str(pg, "offsetParam")) || string.IsNullOrWhiteSpace(Str(pg, "limitParam")))) why.Add("mapping.operations.listOpen.paging needs offsetParam and limitParam for offset paging");
            }
            if (k is "update" or "close" or "reopen" && !TemplateTokens(Prop(op, "url")).Contains("external.id") && !TemplateTokens(Prop(op, "body")).Contains("external.id"))
                why.Add($"mapping.operations.{k} never names {{{{external.id}}}} -- it could not address the item SecurityInsight created");
            if (Prop(op, "successCodes") is { ValueKind: JsonValueKind.Array } codes)
                foreach (var c in codes.EnumerateArray())
                    if (!int.TryParse(c.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n < 100 || n > 399) why.Add($"mapping.operations.{k}.successCodes: '{c}' is not a 1xx-3xx status");
        }
        foreach (var t in TemplateTokens(m).Distinct())
        {
            var s = SettingToken().Match(t);
            if (s.Success) { if (!settings.Contains(s.Groups[1].Value)) why.Add($"the mapping uses {{{{{t}}}}}, but the settings have no '{s.Groups[1].Value}'"); }
            else if (!Tokens.Contains(t)) why.Add($"the mapping uses {{{{{t}}}}}, which is not a known field ({string.Join(", ", Tokens)}, settings.<name>)");
        }
        foreach (var p in LiteralSecrets(m, "mapping")) why.Add($"{p} looks like a secret value -- put the secret in Key Vault, name it under secret references and point to it with a *Ref field");
    }

    /// The reasons a write is refused (empty = accepted). Sends nothing. The same rules as ConvertFrom-SIConnectorRow.
    public static IReadOnlyList<string> Validate(ConnectorWrite w)
    {
        var why = new List<string>();
        if (w.Action is not ("Set" or "Reset")) return new[] { $"unknown action '{w.Action}'" };
        if (!NamePattern().IsMatch(w.Name ?? "")) why.Add($"the name '{w.Name}' must be 2-63 lower-case letters, digits and dashes");
        if (w.Action == "Reset")
        {
            if (w.ExpectedVersion is null) why.Add($"the connector {w.Name} does not exist -- nothing to remove");
            return why;
        }
        if (!Kinds.Contains(w.Kind)) why.Add($"the kind '{w.Kind}' is not one of {string.Join(", ", Kinds)}");
        if (!Directions.Contains(w.Direction)) why.Add($"the direction '{w.Direction}' is not one of {string.Join(", ", Directions)}");
        else if (w.Direction == "cmdb" && !CmdbKinds.Contains(w.Kind)) why.Add("only a servicenow or sql connector can have the cmdb direction");
        else if (w.Direction == ServiceNowDataOut.Direction && w.Kind != "servicenow") why.Add("only a servicenow connector can have the data-out direction");
        if (!Modes.Contains(w.Mode)) why.Add($"the mode '{w.Mode}' is not whatif or apply");

        var (settings, sErr) = Parse(w.SettingsJson, "the settings");
        if (sErr is not null) why.Add(sErr);
        foreach (var p in LiteralSecrets(settings, "settings")) why.Add($"{p} looks like a secret value -- the settings hold no secrets; put it in Key Vault and name it under secret references");
        var (refs, rErr) = Parse(w.SecretRefsJson, "the secret references");
        if (rErr is not null) why.Add(rErr);
        var refNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (refs is { } re)
            foreach (var p in re.EnumerateObject())
            {
                refNames.Add(p.Name);
                if (p.Value.ValueKind != JsonValueKind.String || !IsSecretName(p.Value.GetString()))
                    why.Add($"the secret reference '{p.Name}' must be a Key Vault secret NAME (letters, digits, dashes) -- never the secret itself");
            }
        var (mapping, mErr) = Parse(w.MappingJson, "the mapping");
        if (mErr is not null) why.Add(mErr);
        var settingNames = new HashSet<string>(Keys(settings), StringComparer.OrdinalIgnoreCase);
        switch (w.Kind)
        {
            case "sql":
                if (string.IsNullOrWhiteSpace(Str(settings, "server")) || string.IsNullOrWhiteSpace(Str(settings, "database"))) why.Add("a sql connector needs settings.server and settings.database");
                break;
            case "servicenow":
                if (w.Direction == "vulnerability" && string.IsNullOrWhiteSpace(Str(settings, "table"))) why.Add("a servicenow connector needs settings.table (the vulnerable-item table)");
                if ((Str(settings, "instance") ?? "").StartsWith("http://", StringComparison.OrdinalIgnoreCase)) why.Add("settings.instance must be https");
                // the instance URL: https, a host name, no path or query (Connectors > Setup's ServiceNow guide normalises it)
                else if (Str(settings, "instance") is { Length: > 0 } inst && SI.Management.Web.Outputs.ServiceNowInstanceUrl.Validate(inst).Problem is { } instWhy) why.Add("settings.instance: " + instWhy);
                // #903: an API key OR a user and a password -- both, or half of one, is refused here (the engine warns on both)
                if (rErr is null && SI.Management.Web.Outputs.ServiceNowCredential.Problem(w.SecretRefsJson) is { } credWhy) why.Add(credWhy);
                break;
            case "rest":
                if (sErr is null && rErr is null && mErr is null) Mapping(mapping, refNames, settingNames, w.AllowCreate, w.AllowClose, why);
                break;
        }
        return why;
    }

    /// The ChangeLog text of a definition: every field; secret references are names, so there is nothing to hide.
    public static string DefinitionJson(ConnectorWrite w) => JsonSerializer.Serialize(new
    {
        w.Name, w.Kind, w.Direction, w.Enabled, w.Mode, w.AllowCreate, w.AllowClose, w.SettingsJson, w.SecretRefsJson, w.MappingJson,
    });

    private static string? Compact(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var d = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(d.RootElement);
    }

    public async Task<WriteResult> WriteAsync(ConnectorWrite w, string by, CancellationToken ct)
    {
        var why = Validate(w);
        if (why.Count > 0) return new WriteResult(WriteStatus.Refused, $"connector {w.Name}: " + string.Join("; ", why));
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var reason = string.IsNullOrWhiteSpace(w.Reason) ? null : w.Reason.Trim();
        if (reason is { Length: > 400 }) reason = reason[..400];
        var reset = w.Action == "Reset";
        var rows = await _sql.QueryAsync(WriteSql, new Dictionary<string, object?>
        {
            ["Name"] = w.Name, ["Action"] = w.Action, ["Kind"] = w.Kind, ["Direction"] = w.Direction, ["Enabled"] = w.Enabled, ["Mode"] = w.Mode,
            ["AllowCreate"] = w.AllowCreate, ["AllowClose"] = w.AllowClose,
            ["SettingsJson"] = reset ? null : Compact(w.SettingsJson), ["SecretRefsJson"] = reset ? null : Compact(w.SecretRefsJson), ["MappingJson"] = reset ? null : Compact(w.MappingJson),
            ["Expected"] = w.ExpectedVersion, ["New"] = reset ? null : DefinitionJson(w), ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = reason,
        }, ct);
        return (rows.Count > 0 ? rows[0].Str("Outcome") : null) switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"connector {w.Name} " + (reset ? "removed" : "saved")),
            "Stale" => new WriteResult(WriteStatus.Stale, $"connector {w.Name} changed since it was staged -- nothing was written; stage it again"),
            "Missing" => new WriteResult(WriteStatus.Refused, MissingTableMessage),
            "Conflict" => new WriteResult(WriteStatus.Refused, $"connector {w.Name}: refused -- two ServiceNow data-out connectors would be switched on; switch the other one off (in the same commit, or first). Nothing was written."),
            _ => throw new InvalidOperationException("the connector write returned no outcome"),
        };
    }
}
