using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Auth;
using SI.Management.Web.Data;

namespace SI.Management.Web.Audit;

/// <summary>
/// THE CLOSED LIST of audit actions (#260, framework AUDIT-1.1), read from config\audit-actions.locked.json -- the same
/// file the PowerShell writer (engine\pro-settings\SI-Audit.ps1) reads, linked into the build like the settings catalog.
/// <see cref="All"/> = the listed actions plus the change rows' <c>&lt;category&gt;.change.&lt;verb&gt;</c> (written by the
/// cfg.ChangeLog trigger). A test compares this list with PowerShell's.
/// </summary>
public sealed partial class AuditActions
{
    public IReadOnlyList<string> Listed { get; }
    public IReadOnlyList<string> ChangeCategories { get; }
    public IReadOnlyList<string> ChangeVerbs { get; }
    public IReadOnlyList<string> ActorSources { get; }
    public IReadOnlyList<string> Outcomes { get; }
    /// Every action a row may carry, sorted ordinally.
    public IReadOnlyList<string> All { get; }
    /// The action domains (the first segment) -- the Audit view's category filter.
    public IReadOnlyList<string> Categories { get; }
    private readonly HashSet<string> _all;

    public AuditActions(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        static IReadOnlyList<string> Strings(JsonElement e, string name) => e.GetProperty(name).EnumerateArray().Select(x => x.GetString()!).ToList();
        Listed = r.GetProperty("actions").EnumerateArray().Select(a => a.GetProperty("action").GetString()!).ToList();
        ChangeCategories = Strings(r, "changeCategories");
        ChangeVerbs = Strings(r, "changeVerbs");
        ActorSources = Strings(r, "actorSources");
        Outcomes = Strings(r, "outcomes");
        All = Listed.Concat(ChangeCategories.SelectMany(c => ChangeVerbs.Select(v => $"{c}.change.{v}"))).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
        foreach (var a in All) if (!Shape().IsMatch(a)) throw new InvalidOperationException($"audit action '{a}' is not lower-case domain.object.verb");
        _all = new HashSet<string>(All, StringComparer.Ordinal);
        Categories = All.Select(a => a[..a.IndexOf('.')]).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
    }

    public bool IsKnown(string? action) => action is not null && _all.Contains(action);

    [GeneratedRegex("^[a-z][a-z0-9-]*\\.[a-z][a-z0-9-]*\\.[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant)]
    public static partial Regex Shape();

    public const string FileName = "audit-actions.locked.json";
    /// Next to the app (catalog\audit-actions.locked.json, linked by the csproj).
    public static string DefaultPath => Path.Combine(AppContext.BaseDirectory, "catalog", FileName);
    private static readonly Lazy<AuditActions> Shipped = new(() => new AuditActions(File.ReadAllText(Locate())));

    /// The linked copy next to the app; else (a source-tree run) config\ of the SecurityInsight folder above it.
    public static string Locate()
    {
        if (File.Exists(DefaultPath)) return DefaultPath;
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "config", FileName);
            if (File.Exists(p)) return p;
        }
        throw new FileNotFoundException("the audit action list is missing", DefaultPath);
    }
    public static AuditActions Default => Shipped.Value;
}

/// The handler's audit action (one of <see cref="AuditActions"/>). Every mutating handler carries it, or <see cref="NotAuditedAttribute"/>.
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class AuditedAttribute(string action) : Attribute
{
    public string Action { get; } = action;
}

/// A mutating-verb handler that is NOT audited, with the reason. The set of these is a CLOSED list kept in a test.
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class NotAuditedAttribute(string reason) : Attribute
{
    public string Reason { get; } = reason;
}

public static class AuditOutcomes
{
    public const string Ok = "ok";
    public const string Error = "error";
    public const string Refused = "refused";
    public const string Held = "held";
}

public static class AuditSources
{
    public const string Web = "web";
    public const string Portal = "portal";
}

/// One row of the trail as a writer hands it over. TsUtc is never here: the store sets it.
public sealed record AuditRecord(string Action, string Actor, string ActorSource, string Outcome)
{
    public string? Target { get; init; }
    public string? Reason { get; init; }
    public string? OutcomeText { get; init; }
    public string? BeforeJson { get; init; }
    public string? AfterJson { get; init; }
    public string? CorrelationId { get; init; }
    public bool WhatIf { get; init; }
    public string? ScopeDomain { get; init; }
    public int? ScopeDepartmentId { get; init; }
}

/// <summary>
/// The audit context of ONE request (or one step): what the filter will write, which the handler may sharpen (target,
/// outcome, before / after, the exported row count). Ambient through <see cref="Current"/> (AsyncLocal), so the SQL
/// executor can put the correlation id into SESSION_CONTEXT and the cfg.ChangeLog trigger joins the change rows to it,
/// and so the role framework can note the target's domain / department as it checks it.
/// </summary>
public sealed class AuditScope
{
    private static readonly AsyncLocal<AuditScope?> Ambient = new();
    public static AuditScope? Current => Ambient.Value;

    public AuditScope(string action, string actor, string actorSource)
    {
        Action = action; Actor = actor; ActorSource = actorSource;
        CorrelationId = Guid.NewGuid().ToString("N");
    }

    public string Action { get; set; }
    public string Actor { get; set; }
    public string ActorSource { get; set; }
    public string CorrelationId { get; }
    public string? Target { get; set; }
    public string? Reason { get; set; }
    public string? Outcome { get; private set; }
    public string? OutcomeText { get; private set; }
    public string? BeforeJson { get; set; }
    public string? AfterJson { get; set; }
    public bool WhatIf { get; set; }
    public string? Domain { get; set; }
    public int? DepartmentId { get; set; }
    /// The rows an export carried (null = not counted).
    public long? Rows { get; set; }
    /// The filter of an export, as the handler describes it (else the query string).
    public string? Filter { get; set; }

    public void Set(string outcome, string? text = null) { Outcome = outcome; OutcomeText = text; }
    public void Refused(string? why) => Set(AuditOutcomes.Refused, why);
    public void Failed(string? why) => Set(AuditOutcomes.Error, why);

    /// The role framework noted the target of a scoped check (first one wins; a bulk over several domains leaves none).
    public void NoteTarget(string? domain, int? department)
    {
        if (domain is not null && Domain is null) Domain = domain;
        if (department is not null && DepartmentId is null) DepartmentId = department;
    }

    /// Makes this the ambient scope until the returned handle is disposed.
    public IDisposable Enter()
    {
        var prev = Ambient.Value;
        Ambient.Value = this;
        return new Restore(prev);
    }

    private sealed class Restore(AuditScope? prev) : IDisposable
    {
        public void Dispose() => Ambient.Value = prev;
    }

    // #404 (framework CONFIG-1.1): what the change journal's triggers record beyond the trail -- the journal source
    // (gui unless a handler says restore / undo / import), the person who initiated the change when it is not the actor
    // (an approver committing a colleague's request), the approver, the commit an undo reverses, and the reason.
    public string? ConfigSource { get; set; }
    public string? ConfigInitiatedBy { get; set; }
    public string? ConfigApprovedBy { get; set; }
    public string? ConfigUndoOf { get; set; }
    public string? ConfigReason { get; set; }

    /// Sets the journal context for one write and puts the previous one back when disposed (a commit of several staged
    /// changes writes each with its own source / undo-of under the ONE commit id).
    public IDisposable Journal(string? source, string? undoOf = null, string? initiatedBy = null, string? approvedBy = null, string? reason = null)
    {
        var prev = (ConfigSource, ConfigUndoOf, ConfigInitiatedBy, ConfigApprovedBy, ConfigReason);
        ConfigSource = source; ConfigUndoOf = undoOf; ConfigInitiatedBy = initiatedBy; ConfigApprovedBy = approvedBy; ConfigReason = reason;
        return new JournalRestore(this, prev);
    }

    private sealed class JournalRestore(AuditScope s, (string?, string?, string?, string?, string?) prev) : IDisposable
    {
        public void Dispose() => (s.ConfigSource, s.ConfigUndoOf, s.ConfigInitiatedBy, s.ConfigApprovedBy, s.ConfigReason) = prev;
    }

    /// The SESSION_CONTEXT keys the cfg.ChangeLog trigger and the change journal's triggers read (sql\si-pro-settings.sql).
    public IReadOnlyDictionary<string, object?> SessionContext() => new Dictionary<string, object?>
    {
        ["si.audit.cid"] = CorrelationId,
        ["si.audit.source"] = ActorSource,
        ["si.audit.domain"] = Domain,
        ["si.audit.department"] = DepartmentId?.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["si.audit.actor"] = Actor,
        ["si.cfg.source"] = ConfigSource,
        ["si.cfg.initiatedBy"] = ConfigInitiatedBy,
        ["si.cfg.approvedBy"] = ConfigApprovedBy,
        ["si.cfg.undoOf"] = ConfigUndoOf,
        ["si.cfg.reason"] = ConfigReason is { Length: > 400 } r ? r[..400] : ConfigReason,
    };

    public AuditRecord ToRecord(string outcome, string? outcomeText) => new(Action, Actor, ActorSource, outcome)
    {
        Target = Target, Reason = Reason, OutcomeText = outcomeText, BeforeJson = BeforeJson, AfterJson = AfterJson,
        CorrelationId = CorrelationId, WhatIf = WhatIf, ScopeDomain = Domain, ScopeDepartmentId = DepartmentId,
    };

    /// Who did it, as recorded: the UPN (Entra), the sign-in link's person, or "anonymous". Never the process identity.
    public static string ActorOf(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true) return "anonymous";
        var n = user.ChangeName();
        return string.IsNullOrWhiteSpace(n) ? "signed-in user (no name)" : n;
    }

    /// web for an Entra sign-in; portal for a magic-link / department sign-in-link session.
    public static string SourceOf(ClaimsPrincipal? user) =>
        user?.Identity?.IsAuthenticated == true && AuthMethods.Of(user) != AuthMethods.OAuth ? AuditSources.Portal : AuditSources.Web;
}

/// The health of the audit writer: a failed write never fails the action, but it is COUNTED and shown (AUDIT-1.3).
public sealed class AuditHealth
{
    private long _failed;
    private long _written;
    public long Failed => Interlocked.Read(ref _failed);
    public long Written => Interlocked.Read(ref _written);
    public string? LastError { get; private set; }
    public DateTime? LastFailureUtc { get; private set; }
    internal void Ok() => Interlocked.Increment(ref _written);
    internal void Fail(string error) { Interlocked.Increment(ref _failed); LastError = error; LastFailureUtc = DateTime.UtcNow; }
}

public interface IAuditWriter
{
    /// Writes one row. Never throws (except cancellation): a failure is logged, counted in <see cref="AuditHealth"/>, and
    /// answered false.
    Task<bool> WriteAsync(AuditRecord record, CancellationToken ct);
}

/// <summary>THE web writer: one INSERT into cfg.AuditEvent (TsUtc is the store's). No other statement touches the table.</summary>
public sealed class SqlAuditWriter : IAuditWriter
{
    public const string InsertSql = """
IF OBJECT_ID(N'cfg.AuditEvent') IS NULL
    SELECT N'Missing' AS Outcome;
ELSE
BEGIN
    INSERT cfg.AuditEvent (RecordType, Action, Actor, ActorSource, Target, Reason, Outcome, OutcomeText, BeforeJson, AfterJson, CorrelationId, WhatIf, ScopeDomain, ScopeDepartmentId)
    VALUES (N'event', @Action, @Actor, @ActorSource, @Target, @Reason, @Outcome, @OutcomeText, @BeforeJson, @AfterJson, @CorrelationId, @WhatIf, @ScopeDomain, @ScopeDepartmentId);
    SELECT N'Saved' AS Outcome;
END
""";

    private readonly ISqlExecutor _sql;
    private readonly AuditHealth _health;
    private readonly AuditActions _actions;
    private readonly ILogger<SqlAuditWriter> _log;

    public SqlAuditWriter(ISqlExecutor sql, AuditHealth health, AuditActions actions, ILogger<SqlAuditWriter> log)
    { _sql = sql; _health = health; _actions = actions; _log = log; }

    public static IReadOnlyDictionary<string, object?> Parameters(AuditRecord r) => new Dictionary<string, object?>
    {
        ["Action"] = Cut(r.Action, 64),
        ["Actor"] = Cut(string.IsNullOrWhiteSpace(r.Actor) ? "(unknown)" : r.Actor, 256),
        ["ActorSource"] = r.ActorSource,
        ["Target"] = Cut(r.Target, 400),
        ["Reason"] = Cut(r.Reason, 400),
        ["Outcome"] = r.Outcome,
        ["OutcomeText"] = Cut(AuditRedaction.Text(r.OutcomeText), 1000),
        ["BeforeJson"] = r.BeforeJson,
        ["AfterJson"] = r.AfterJson,
        ["CorrelationId"] = r.CorrelationId,
        ["WhatIf"] = r.WhatIf,
        ["ScopeDomain"] = Cut(r.ScopeDomain, 64),
        ["ScopeDepartmentId"] = r.ScopeDepartmentId,
    };

    private static string? Cut(string? s, int n) => s is null ? null : s.Length > n ? s[..n] : s;

    public async Task<bool> WriteAsync(AuditRecord record, CancellationToken ct)
    {
        try
        {
            if (!_actions.IsKnown(record.Action)) _log.LogError("audit action {Action} is not on the closed list (config\\audit-actions.locked.json) -- written anyway", record.Action);
            var rows = await _sql.QueryAsync(InsertSql, Parameters(record), ct);
            if (rows.FirstOrDefault()?.Str("Outcome") == "Missing")
            {
                // the schema is older than the trail: said in the log and counted, the action itself is not affected
                _health.Fail("the Pro database has no cfg.AuditEvent yet -- apply sql\\si-pro-settings.sql (it only adds)");
                _log.LogWarning("audit row {Action} not written: cfg.AuditEvent does not exist yet", record.Action);
                return false;
            }
            _health.Ok();
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _health.Fail(ex.Message);
            _log.LogError(ex, "audit row {Action} by {Actor} ({Outcome}) could not be written", record.Action, record.Actor, record.Outcome);
            return false;
        }
    }
}

/// <summary>What never reaches the trail: secrets, tokens, codes, passwords -- by field name, and token-shaped text.</summary>
public static partial class AuditRedaction
{
    public const string Hidden = "(hidden)";

    /// A form / query field whose value is a secret or a credential.
    public static bool IsSecretField(string name) =>
        name.StartsWith("__", StringComparison.Ordinal) || SecretName().IsMatch(name);

    [GeneratedRegex("(?i)(secret|password|passwd|^pwd$|token|^otp|otp$|^pin$|code$|credential|apikey|api_key|signature|cookie|^t$|^sig$)", RegexOptions.CultureInvariant)]
    private static partial Regex SecretName();

    /// A long opaque run (a token, a key: 40+ characters with no '/', '.' or space -- a resource id or a path is not one)
    /// inside free text is cut out.
    [GeneratedRegex("(?<![A-Za-z0-9_\\-+=])(?=[A-Za-z0-9_\\-+=]*[0-9])(?=[A-Za-z0-9_\\-+=]*[A-Za-z])[A-Za-z0-9_\\-+=]{40,}", RegexOptions.CultureInvariant)]
    private static partial Regex Opaque();

    public static string? Text(string? s) => s is null ? null : Opaque().Replace(s, Hidden);

    /// The request's fields as JSON: secret fields hidden, values cut at 2,000 characters, at most 60 fields, files by
    /// name and size only.
    public static string? Form(IEnumerable<KeyValuePair<string, string[]>> fields, IEnumerable<(string Name, string File, long Length)>? files = null)
    {
        var o = new SortedDictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (k, v) in fields)
        {
            if (o.Count >= 60) break;
            if (string.IsNullOrEmpty(k) || k.StartsWith("__", StringComparison.Ordinal)) continue;
            if (IsSecretField(k)) { o[k] = Hidden; continue; }
            var vals = v.Select(x => x is null ? null : Text(x.Length > 2000 ? x[..2000] + "..." : x)).ToArray();
            o[k] = vals.Length == 1 ? vals[0] : vals;
        }
        foreach (var f in files ?? Array.Empty<(string, string, long)>()) o["file:" + f.Name] = $"{f.File} ({f.Length} bytes)";
        return o.Count == 0 ? null : JsonSerializer.Serialize(o);
    }
}
