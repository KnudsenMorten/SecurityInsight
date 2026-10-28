using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Guards;

/// <summary>
/// #277 -- the closed list of guards (config\guard-catalog.locked.json, linked by the csproj): the SAME file the
/// PowerShell guard events read (engine\_shared\SI-Guard.ps1). Every guard that holds, refuses or halts a step to protect
/// data has one entry: its stable dotted id, its area, what it protects and what a person should do -- the words of the
/// mail.
/// </summary>
public sealed partial class GuardCatalog
{
    /// One guard. <paramref name="Kind"/> says what "release" means for it (see <see cref="GuardKinds"/>); What / Why /
    /// Consequence / Steps are the three parts a person reads plus what to do, as templates (<see cref="GuardText"/>).
    public sealed record Entry(string Id, string Area, string Job, string Protects, string Action,
        string Kind = GuardKinds.Info, string What = "", string Why = "", string Consequence = "", IReadOnlyList<string>? Steps = null, string NeverReleasable = "",
        string Name = "", string IfRelease = "", string WhenOff = "", IReadOnlyList<string>? Limits = null, string LimitsInfo = "")
    {
        public IReadOnlyList<string> StepList => Steps ?? Array.Empty<string>();
        /// The settings that tune this guard (its limits), edited on the Guards page under Control.
        public IReadOnlyList<string> LimitList => Limits ?? Array.Empty<string>();
        /// The short plain name a person reads (operator 2026-10-09: "nobody understand the context") -- the id stays small.
        public string Title => string.IsNullOrWhiteSpace(Name) ? Protects : Name;
        /// GUARD-1.6: only a held set or a held collection can be released; every other guard says why it never can.
        public bool Releasable => Kind is GuardKinds.ReleaseHeldSet or GuardKinds.ReleaseCollection;
    }

    /// <summary>
    /// #448 (operator 2026-10-09: "only the two limits, a database change that removes data, and an empty/collapsed result
    /// overwriting good data ever hold"): the ONLY checks that may hold or stop a change. Every other check WARNS (the
    /// badge and the mail) and never blocks work. A Risk Analysis run that only partly finished is loaded, marked partial;
    /// a held collection is left only for a run that failed outright.
    /// </summary>
    public static readonly IReadOnlySet<string> MayHold = new HashSet<string>(StringComparer.Ordinal)
    {
        "vuln.connector.close-ceiling",          // limit 1: close at most __% of open vulnerabilities in one run
        "cmdb.handoff.mass-change",              // limit 2: change at most __% of CMDB items in one run
        "asset.properties.collection-change",    // limit 2 (the asset data that feeds the CMDB)
        "schema.gate.refused",                   // a database change that removes data
        "vuln.connector.empty-snapshot", "vuln.connector.collapse",   // an empty or collapsed result about to close good records
        "cmdb.sql.empty-snapshot", "cmdb.sql.collapse",               // ... or retire good CIs
        "datasync.collection.held",              // only a run that failed outright (a partial run is loaded, marked partial)
    };

    public IReadOnlyList<Entry> Guards { get; }
    public IReadOnlyList<string> Outcomes { get; }
    public IReadOnlyDictionary<string, string> Severity { get; }
    public IReadOnlyList<string> Areas { get; }
    private readonly Dictionary<string, Entry> _byId;

    public GuardCatalog(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        Outcomes = r.GetProperty("outcomes").EnumerateArray().Select(x => x.GetString()!).ToList();
        Severity = r.GetProperty("severity").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!, StringComparer.Ordinal);
        static string Opt(JsonElement g, string n) => g.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        Guards = r.GetProperty("guards").EnumerateArray().Select(g => new Entry(g.GetProperty("id").GetString()!, g.GetProperty("area").GetString()!,
            g.GetProperty("job").GetString() ?? "", g.GetProperty("protects").GetString()!, g.GetProperty("action").GetString()!,
            Opt(g, "kind") is { Length: > 0 } k ? k : GuardKinds.Info, Opt(g, "what"), Opt(g, "why"), Opt(g, "consequence"),
            g.TryGetProperty("steps", out var st) && st.ValueKind == JsonValueKind.Array ? st.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList() : [],
            Opt(g, "neverReleasable"), Opt(g, "name"), Opt(g, "ifRelease"), Opt(g, "whenOff"),
            g.TryGetProperty("limits", out var li) && li.ValueKind == JsonValueKind.Array ? li.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList() : [],
            Opt(g, "limitsInfo"))).ToList();
        foreach (var g in Guards) if (!IdShape().IsMatch(g.Id)) throw new InvalidOperationException($"guard id '{g.Id}' is not area.object.what");
        foreach (var g in Guards) if (!GuardKinds.All.Contains(g.Kind)) throw new InvalidOperationException($"guard '{g.Id}' has kind '{g.Kind}', which is not one of {string.Join(", ", GuardKinds.All)}");
        _byId = Guards.ToDictionary(g => g.Id, StringComparer.Ordinal);
        Areas = Guards.Select(g => g.Area).Distinct().OrderBy(a => a, StringComparer.Ordinal).ToList();
    }

    public Entry? Find(string id) => _byId.GetValueOrDefault(id);
    public string SeverityOf(string outcome) => Severity.TryGetValue(outcome, out var s) ? s : throw new ArgumentException($"'{outcome}' is not a guard outcome");

    [GeneratedRegex("^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*){2}$", RegexOptions.CultureInvariant)]
    public static partial Regex IdShape();

    public const string FileName = "guard-catalog.locked.json";
    public static string DefaultPath => Path.Combine(AppContext.BaseDirectory, "catalog", FileName);
    private static readonly Lazy<GuardCatalog> Shipped = new(() => new GuardCatalog(File.ReadAllText(Locate())));

    /// The linked copy next to the app; else (a source-tree run) config\ of the SecurityInsight folder above it.
    public static string Locate()
    {
        if (File.Exists(DefaultPath)) return DefaultPath;
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "config", FileName);
            if (File.Exists(p)) return p;
        }
        throw new FileNotFoundException("the guard catalog is missing", DefaultPath);
    }
    public static GuardCatalog Default => Shipped.Value;
}

/// What "release" means for a guard (the catalog's 'kind'). Every event can ALSO be acknowledged.
public static class GuardKinds
{
    /// An Admin releases the set the guard held, once (the vulnerability connector's held closes, a held asset-properties
    /// collection, a held CMDB hand-off batch): cfg.GuardRelease, Operations &gt; Guards.
    public const string ReleaseHeldSet = "release-held-set";
    /// An Admin loads a held Risk Analysis collection once, MARKED PARTIAL wherever it is shown.
    public const string ReleaseCollection = "release-collection";
    /// Cannot be released: the data itself is wrong; fix the cause.
    public const string FixSource = "fix-source";
    /// Resolved by the next successful run.
    public const string NextRun = "next-run";
    /// Re-run the job (Operations &gt; Jobs).
    public const string Rerun = "rerun";
    /// Change a setting or the licence.
    public const string Setting = "setting";
    /// Check the result before trusting it.
    public const string Review = "review";
    /// Nothing to do.
    public const string Info = "info";
    public static readonly IReadOnlyList<string> All = [ReleaseHeldSet, ReleaseCollection, FixSource, NextRun, Rerun, Setting, Review, Info];

    /// The words of the Action column for a kind that is not released by a button.
    public static string Label(string kind) => kind switch
    {
        ReleaseHeldSet => "Release (SuperAdmin, once)",
        ReleaseCollection => "Release: load this collection anyway",
        FixSource => "Can't be released: fix the source",
        NextRun => "Resolved by the next successful run",
        Rerun => "Re-run the job",
        Setting => "Change the setting",
        Review => "Review the result",
        _ => "Nothing to do",
    };
}

/// One measured value against its limit (the mail's table, the telemetry's Measured / Thresholds).
public sealed record GuardValue(string Name, string Label, double? Measured, double? Limit, string? Unit = null)
{
    /// CR4 (#654): the configured limit when <see cref="Limit"/> is the one halved in the stricter period after a release.
    public double? Configured { get; init; }
}

/// One row of the Guards view. Ack = "open" | "acknowledged" (cfg.GuardAck: this event, or an earlier acknowledgement of
/// exactly the same event -- the same guard key and detail).
public sealed record GuardRow(long Id, DateTime? TsUtc, string GuardId, string Area, string? Job, string Outcome, string Severity, string? Protected,
    string? Subject, string? Detail, string? Measured, long Held, int Trips, string MailState, string TelemetryState, string? ActionText, string? Source, string? RunId = null,
    string? ValuesJson = null, string Ack = "open", string? AckBy = null, DateTime? AckUtc = null,
    string? Version = null, string? Attribution = null, string? ClearedText = null)
{
    public bool Acknowledged => string.Equals(Ack, "acknowledged", StringComparison.OrdinalIgnoreCase);
    /// Owner 2026-10-17 (guards heal themselves): the row IS a clear ("Back to normal in run ... on version ..." or the
    /// owner's acceptance), or a later clear of the same guard key closed it.
    public bool IsClear => string.Equals(Outcome, ClearOutcome, StringComparison.OrdinalIgnoreCase);
    public bool Cleared => string.Equals(Ack, "cleared", StringComparison.OrdinalIgnoreCase);
    /// A drop confirmed at its new level (2 runs at the same level): the episode closed, but it is NOT a heal -- the row
    /// stays open until a person acknowledges it, and the trips it closed read "Taken as the new level".
    public bool IsTaken => string.Equals(Outcome, TakenOutcome, StringComparison.OrdinalIgnoreCase);
    public bool Taken => string.Equals(Ack, "taken", StringComparison.OrdinalIgnoreCase);
    public const string TakenOutcome = "taken";
    /// A trip the owner accepted for its version (recorded, not mailed, not reported again).
    public bool Accepted => string.Equals(Ack, "accepted", StringComparison.OrdinalIgnoreCase);
    public const string ClearOutcome = "cleared";

    /// The measured values of the event (ValuesJson), for the {v:name} placeholders.
    public IReadOnlyList<GuardValue> Values()
    {
        if (string.IsNullOrWhiteSpace(ValuesJson)) return Array.Empty<GuardValue>();
        try
        {
            using var doc = JsonDocument.Parse(ValuesJson);
            var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList()
                : doc.RootElement.ValueKind == JsonValueKind.Object ? [doc.RootElement] : [];
            static double? N(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;
            static string? T(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            return items.Where(e => e.ValueKind == JsonValueKind.Object).Select(e => new GuardValue(T(e, "Name") ?? "", T(e, "Label") ?? "", N(e, "Measured"), N(e, "Limit"), T(e, "Unit")) { Configured = N(e, "Configured") })
                .Where(v => v.Name.Length > 0).ToList();
        }
        catch (JsonException) { return Array.Empty<GuardValue>(); }
    }

    public static GuardRow From(IReadOnlyDictionary<string, object?> r)
    {
        string? S(string k) => r.TryGetValue(k, out var v) && v is not null && v is not DBNull ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
        long L(string k) => r.TryGetValue(k, out var v) && v is not null && v is not DBNull ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : 0;
        var when = r.TryGetValue("Ts", out var t) && t is DateTime d ? d : (DateTime?)null;
        var ackAt = r.TryGetValue("AckUtc", out var a) && a is DateTime ad ? ad : (DateTime?)null;
        return new GuardRow(L("Id"), when, S("Guard") ?? "", S("Area") ?? "", S("Job"), S("Outcome") ?? "", S("Severity") ?? "", S("Protected"), S("Subject"),
            S("Detail"), S("Measured"), L("Held"), (int)L("Trips"), S("Mail") ?? "", S("Telemetry") ?? "", S("ActionText"), S("Source"), S("RunId"),
            S("ValuesJson"), S("Ack") ?? "open", S("AckBy"), ackAt, S("Version"), S("Attribution"), S("Cleared"));
    }
}

/// <summary>
/// The Guards view's reads and the web app's own guard writes, over cfg.GuardEvent (sql\si-pro-settings.sql).
/// </summary>
public interface IGuardEventStore
{
    Task<bool> ExistsAsync(CancellationToken ct);
    Task<(IReadOnlyList<GuardRow> Rows, long Total, string Query)> PageAsync(GridState st, DateTime? from, CancellationToken ct);
    /// #287: how many events each value of one value-filter column has under the OTHER filters (none = shown without counts).
    Task<IReadOnlyList<(string Value, long N)>> ValueCountsAsync(GridState st, DateTime? from, string column, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<(string Value, long N)>>(Array.Empty<(string, long)>());
    /// One row, mail and telemetry 'pending' (the mail job sends them). False when it could not be written.
    Task<bool> WriteAsync(IReadOnlyDictionary<string, object?> row, CancellationToken ct);
    /// cfg.GuardAck exists (acknowledging is possible, and acknowledged events can be hidden).
    Task<bool> CanAcknowledgeAsync(CancellationToken ct) => Task.FromResult(false);
    /// One event (and every later repeat of exactly it) acknowledged by <paramref name="by"/>. "Acknowledged" | "Already" |
    /// "Missing" (no such event) | "NoTable".
    Task<string> AcknowledgeAsync(long eventId, string by, string? note, CancellationToken ct) => Task.FromResult("NoTable");
    /// One event by id (for the release and acknowledge handlers), or null.
    Task<GuardRow?> FindAsync(long eventId, CancellationToken ct) => Task.FromResult<GuardRow?>(null);
}

public sealed class SqlGuardEventStore : IGuardEventStore
{
    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.GuardEvent') IS NOT NULL AND OBJECT_ID(N'cfg.GuardState') IS NOT NULL THEN 1 ELSE 0 END AS HasGuards, CASE WHEN OBJECT_ID(N'cfg.GuardAck') IS NOT NULL THEN 1 ELSE 0 END AS HasAck, CASE WHEN COL_LENGTH(N'cfg.GuardEvent', N'Attribution') IS NOT NULL THEN 1 ELSE 0 END AS HasInfo;";

    /// The acknowledgement of one event: once per event; the detail's hash makes later repeats of exactly it acknowledged too.
    public const string AckSql = """
IF OBJECT_ID(N'cfg.GuardAck') IS NULL BEGIN SELECT N'NoTable' AS Outcome; RETURN; END;
DECLARE @k nvarchar(500), @h varbinary(32);
SELECT @k = e.GuardKey, @h = HASHBYTES('SHA2_256', ISNULL(e.Detail, N'')) FROM cfg.GuardEvent AS e WHERE e.Id = @EventId;
IF @k IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.GuardAck AS a WHERE a.EventId = @EventId) BEGIN SELECT N'Already' AS Outcome; RETURN; END;
INSERT cfg.GuardAck (EventId, GuardKey, DetailHash, AckBy, Note) VALUES (@EventId, @k, @h, @By, LEFT(@Note, 1000));
SELECT N'Acknowledged' AS Outcome;
""";

    /// The acknowledgement that covers an event: its own, or one of exactly the same event (key + detail) -- the newest.
    private const string AckApply = """
OUTER APPLY (SELECT TOP (1) a.AckBy, a.AckUtc FROM cfg.GuardAck AS a
             WHERE a.EventId = e.Id OR (a.GuardKey = e.GuardKey AND a.DetailHash = HASHBYTES('SHA2_256', ISNULL(e.Detail, N'')))
             ORDER BY a.AckUtc DESC) AS ak
""";

    /// The PowerShell writer's statement (SI-Guard.ps1 Get-SIGuardSql 'Insert') -- the same columns, the same shape.
    public const string InsertSql = """
INSERT cfg.GuardEvent (GuardId, GuardKey, Area, Job, Engine, Source, Outcome, Severity, Protected, Subject, Detail, MeasuredText, ValuesJson,
                       HeldCount, ActionText, Link, RunId, TripCount, FirstSeenUtc, MailState, MailTo, TelemetryState)
VALUES (@GuardId, @GuardKey, @Area, @Job, @Engine, @Source, @Outcome, @Severity, @Protected, @Subject, @Detail, @MeasuredText, @ValuesJson,
        @HeldCount, @ActionText, @Link, @RunId, @TripCount, @FirstSeenUtc, @MailState, @MailTo, @TelemetryState);
SELECT CAST(SCOPE_IDENTITY() AS BIGINT) AS Id;
""";

    private const string Columns = """
SELECT e.Id AS Id, e.TsUtc AS Ts, e.GuardId AS Guard, e.Area AS Area, e.Job AS Job, e.Outcome AS Outcome, e.Severity AS Severity,
       e.Protected AS Protected, e.Subject AS Subject, e.Detail AS Detail, e.MeasuredText AS Measured, e.HeldCount AS Held, e.TripCount AS Trips,
       e.MailState AS Mail, e.TelemetryState AS Telemetry, e.ActionText AS ActionText, e.Source AS Source, e.RunId AS RunId, e.ValuesJson AS ValuesJson,
""";

    /// Owner 2026-10-17: the version a trip happened on and which release it was (cfg.GuardEvent SiVersion / Attribution, when
    /// the schema has them -- ExistsSql's HasInfo).
    private const string InfoColumns = "       e.SiVersion AS Version, e.Attribution AS Attribution,";
    private const string NoInfoColumns = "       CAST(NULL AS nvarchar(64)) AS Version, CAST(NULL AS nvarchar(400)) AS Attribution,";

    /// Owner 2026-10-17 (guards heal themselves): a later clear of the same guard key -- an engine's "back to normal in run ...
    /// on version ..." or the owner's acceptance -- closes the trip; it reads 'cleared' (not open) with the clear's words.
    private const string ClearApply = """
OUTER APPLY (SELECT TOP (1) c.Detail AS ClearedText, c.Outcome AS ClearedOutcome FROM cfg.GuardEvent AS c
             WHERE c.GuardKey = e.GuardKey AND c.Outcome IN (N'cleared', N'taken') AND c.Id > e.Id ORDER BY c.Id) AS cl
""";

    /// A 'taken' row (a drop confirmed at its new level) stays OPEN until a person acknowledges it -- it is not a heal.
    private static string SourceOf(bool info) => Columns + "\n" + (info ? InfoColumns : NoInfoColumns) + "\n" + """
       CASE WHEN ak.AckBy IS NOT NULL THEN N'acknowledged' WHEN e.Outcome = N'taken' THEN N'open' WHEN e.Outcome = N'cleared' THEN N'cleared'
            WHEN cl.ClearedOutcome = N'taken' THEN N'taken' WHEN cl.ClearedOutcome IS NOT NULL THEN N'cleared'
            WHEN e.MailState = N'accepted' THEN N'accepted' ELSE N'open' END AS Ack, ak.AckBy AS AckBy, ak.AckUtc AS AckUtc,
       CASE WHEN e.Outcome IN (N'cleared', N'taken') THEN e.Detail ELSE cl.ClearedText END AS Cleared
FROM cfg.GuardEvent AS e
""" + "\n" + AckApply + "\n" + ClearApply + "\n" + """
WHERE (@From IS NULL OR e.TsUtc >= @From)
""";

    /// The events with their acknowledgement (cfg.GuardAck), their clear and which release: the grid reads this when the
    /// schema has all of it.
    public static readonly string Source = SourceOf(true);
    /// cfg.GuardAck exists, the version columns not yet (sql\si-pro-settings.sql not applied again).
    public static readonly string SourceWithoutInfo = SourceOf(false);

    /// A database without cfg.GuardAck yet (sql\si-pro-settings.sql not applied again): every event reads open.
    public const string SourceWithoutAck = Columns + "\n" + NoInfoColumns + "\n" + """
       N'open' AS Ack, CAST(NULL AS nvarchar(256)) AS AckBy, CAST(NULL AS datetime2(0)) AS AckUtc, CAST(NULL AS nvarchar(2000)) AS Cleared
FROM cfg.GuardEvent AS e
WHERE (@From IS NULL OR e.TsUtc >= @From)
""";

    public const string FindSql = Columns + "\n" + """
       N'open' AS Ack, CAST(NULL AS nvarchar(256)) AS AckBy, CAST(NULL AS datetime2(0)) AS AckUtc
FROM cfg.GuardEvent AS e
WHERE e.Id = @EventId;
""";

    private static GridSpec Build(string source) => GridSql.Check(new GridSpec("guards", "", source,
    [
        new GridColumn("Id", "#", GridType.Number, GridFilter.Range, SortSql: "(g.[Id] + 0)", Hidden: true),
        new GridColumn("Ts", "When", GridType.Date),
        new GridColumn("Guard", "Guard", GridType.Text, GridFilter.Values, Search: true),
        new GridColumn("Area", "Area", GridType.Text, GridFilter.Values),
        new GridColumn("Measured", "Measured vs limit", GridType.Text, GridFilter.Contains, Search: true),
        new GridColumn("Outcome", "Outcome", GridType.Text, GridFilter.Values),
        new GridColumn("Severity", "Severity", GridType.Text, GridFilter.Values),
        new GridColumn("Ack", "Status", GridType.Text, GridFilter.Values),
        new GridColumn("Held", "Held", GridType.Number, GridFilter.Range),
        new GridColumn("Trips", "Times", GridType.Number, GridFilter.Range),
        new GridColumn("Mail", "Mail", GridType.Text, GridFilter.Values),
        new GridColumn("Telemetry", "Reported", GridType.Text, GridFilter.Values),
        new GridColumn("Subject", "Where", GridType.Text, GridFilter.Contains, Search: true),
        new GridColumn("Detail", "Detail", GridType.Text, Search: true, Sortable: false, Hidden: true),
        new GridColumn("Protected", "Protected", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("ActionText", "What to do", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("Job", "Job", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("Source", "Source", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("RunId", "Run", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("ValuesJson", "Values", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("AckBy", "Acknowledged by", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("AckUtc", "Acknowledged", GridType.Date, Sortable: false, Hidden: true),
        new GridColumn("Version", "Version", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("Attribution", "Which release", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("Cleared", "Cleared", GridType.Text, Sortable: false, Hidden: true),
    ], DefaultSort: "Ts", DefaultDesc: true, KeyColumn: "Id", SourceParameters: ["From"], Immutable: false));   // #317: newest first, on the When column

    /// The grid over the events WITH their acknowledgement (the page's filters and sorts are checked against it).
    public static readonly GridSpec Spec = Build(Source);
    /// The same grid on a database without the version columns yet.
    public static readonly GridSpec SpecWithoutInfo = Build(SourceWithoutInfo);
    /// The same grid on a database without cfg.GuardAck.
    public static readonly GridSpec SpecWithoutAck = Build(SourceWithoutAck);

    private readonly ISqlExecutor _sql;
    public SqlGuardEventStore(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> ExistsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("HasGuards") == 1;

    public async Task<bool> CanAcknowledgeAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("HasAck") == 1;

    private async Task<GridSpec> SpecAsync(CancellationToken ct)
    {
        var r = (await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
        if (r?.Long("HasAck") != 1) return SpecWithoutAck;
        return r?.Long("HasInfo") == 1 ? Spec : SpecWithoutInfo;
    }

    public async Task<(IReadOnlyList<GuardRow> Rows, long Total, string Query)> PageAsync(GridState st, DateTime? from, CancellationToken ct)
    {
        var q = GridSql.Page(await SpecAsync(ct), st, new Dictionary<string, object?> { ["From"] = from });
        var rows = await _sql.QueryAsync(q.Text, q.Parameters, ct);
        return (rows.Select(GuardRow.From).ToList(), rows.FirstOrDefault()?.Long("TotalRows") ?? 0, q.Text);
    }

    public async Task<IReadOnlyList<(string Value, long N)>> ValueCountsAsync(GridState st, DateTime? from, string column, CancellationToken ct)
    {
        var q = GridSql.ValueCounts(await SpecAsync(ct), st, new Dictionary<string, object?> { ["From"] = from }, column);
        return (await _sql.QueryAsync(q.Text, q.Parameters, ct)).Select(r => (r.Str("V") ?? "", r.Long("N") ?? 0)).ToList();
    }

    public async Task<string> AcknowledgeAsync(long eventId, string by, string? note, CancellationToken ct) =>
        (await _sql.QueryAsync(AckSql, new Dictionary<string, object?> { ["EventId"] = eventId, ["By"] = by, ["Note"] = note ?? "" }, ct)).FirstOrDefault()?.Str("Outcome") ?? "Missing";

    public async Task<GuardRow?> FindAsync(long eventId, CancellationToken ct) =>
        (await _sql.QueryAsync(FindSql, new Dictionary<string, object?> { ["EventId"] = eventId }, ct)).Select(r => GuardRow.From(r)).FirstOrDefault();

    public async Task<bool> WriteAsync(IReadOnlyDictionary<string, object?> row, CancellationToken ct)
    {
        if (!await ExistsAsync(ct)) return false;
        await _sql.QueryAsync(InsertSql, row, ct);
        return true;
    }
}

/// <summary>
/// The web app's guard events (the exemption bulk guard), in the SAME shape the PowerShell writer uses. The web app never
/// talks to a mail server or to Invardia: the row is saved with mail and telemetry 'pending', and the mail job
/// (Invoke-SIGuardOutbox in Invoke-SICloseLoopMail.ps1) mails it through the relay -- de-duplicated per guard per day --
/// and reports it to Invardia when status reports are on. Best effort, like the exemption mails: one execution of the mail
/// job is started so the mail goes out in minutes. NEVER throws: a guard event never fails the request it records.
/// </summary>
public sealed class GuardEventWriter
{
    private readonly IGuardEventStore _store;
    private readonly IJobsClient? _jobs;
    private readonly Microsoft.Extensions.Options.IOptions<JobsOptions>? _options;
    private readonly ILogger<GuardEventWriter> _log;
    private readonly GuardSwitches? _switches;
    public GuardCatalog Catalog { get; }

    public GuardEventWriter(IGuardEventStore store, ILogger<GuardEventWriter> log, IJobsClient? jobs = null, Microsoft.Extensions.Options.IOptions<JobsOptions>? options = null, GuardCatalog? catalog = null,
        GuardSwitches? switches = null)
    { _store = store; _log = log; _jobs = jobs; _options = options; Catalog = catalog ?? GuardCatalog.Default; _switches = switches; }

    /// PURE. The row of one event, as SI-Guard.ps1 would write it (measured text "Label: 25.9 % (limit 10 %)").
    public static Dictionary<string, object?> Row(GuardCatalog catalog, string guardId, string outcome, string? subject, string? detail,
        IReadOnlyList<GuardValue> values, long held, string source = "web", string? runId = null, string? link = null)
    {
        var g = catalog.Find(guardId) ?? throw new ArgumentException($"guard '{guardId}' is not in {GuardCatalog.FileName}");
        var sev = catalog.SeverityOf(outcome);
        var sub = Cut(subject?.Trim(), 400);
        static string N(double? v) => v is null ? "unknown" : v.Value == Math.Floor(v.Value) ? v.Value.ToString("N0", CultureInfo.InvariantCulture) : v.Value.ToString("#,0.##", CultureInfo.InvariantCulture);
        var measured = string.Join("; ", values.Select(v =>
        {
            var u = string.IsNullOrEmpty(v.Unit) ? "" : " " + v.Unit;
            var t = $"{v.Label}: {N(v.Measured)}{(v.Measured is null ? "" : u)}";
            if (v.Limit is null) return t;
            // CR4 (#654): a limit halved in the stricter period after a release, with the configured one -- as SI-Guard.ps1 says it
            return v.Configured is { } c && c != v.Limit
                ? t + $" (limit {N(v.Limit)}{u} in the stricter period after a release, normally {N(c)}{u})"
                : t + $" (limit {N(v.Limit)}{u})";
        }));
        var json = JsonSerializer.Serialize(values.Select(v =>
        {
            var o = new Dictionary<string, object?> { ["Name"] = v.Name, ["Label"] = v.Label, ["Measured"] = v.Measured, ["Limit"] = v.Limit, ["Unit"] = v.Unit };
            if (v.Configured is { } c && c != v.Limit) o["Configured"] = c;
            return o;
        }));
        return new Dictionary<string, object?>
        {
            ["GuardId"] = g.Id, ["GuardKey"] = string.IsNullOrEmpty(sub) ? g.Id : g.Id + "|" + sub.ToLowerInvariant(), ["Area"] = g.Area,
            ["Job"] = string.IsNullOrEmpty(g.Job) ? "si-web" : g.Job, ["Engine"] = "web", ["Source"] = source, ["Outcome"] = outcome, ["Severity"] = sev,
            ["Protected"] = g.Protects, ["Subject"] = sub, ["Detail"] = Cut(detail, 2000), ["MeasuredText"] = Cut(measured, 1000), ["ValuesJson"] = json,
            ["HeldCount"] = Math.Max(0, held), ["ActionText"] = g.Action, ["Link"] = link, ["RunId"] = runId ?? Guid.NewGuid().ToString(),
            ["TripCount"] = 1, ["FirstSeenUtc"] = null, ["MailState"] = "pending", ["MailTo"] = null, ["TelemetryState"] = "pending",
        };
    }

    private static string? Cut(string? s, int n) => s is null ? null : s.Length > n ? s[..n] : s;

    public async Task<bool> WriteAsync(string guardId, string outcome, string? subject, string? detail, IReadOnlyList<GuardValue> values, long held, CancellationToken ct)
    {
        try
        {
            // #414: a guard switched off in Settings > Guards makes no event (and so no mail); said once per request in the log
            if (_switches is not null && !await _switches.IsOnAsync(guardId, ct))
            {
                _log.LogInformation("guard {Guard} is off (setting) -- no event", guardId);
                return false;
            }
            var ok = await _store.WriteAsync(Row(Catalog, guardId, outcome, subject, detail, values, held), ct);
            if (!ok) { _log.LogWarning("guard event {Guard} not saved: the Pro database has no guard tables yet (apply sql\\si-pro-settings.sql)", guardId); return false; }
            if (_jobs is { IsConfigured: true } && !string.IsNullOrWhiteSpace(_options?.Value.CloseLoopMailJob))
            {
                try { await _jobs.StartWithEnvAsync(_options!.Value.CloseLoopMailJob, new Dictionary<string, string> { ["SI_EXEMPTION_MAIL_ONLY"] = "1" }, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the mail job could not be started -- the guard mail goes with its next scheduled run"); }
            }
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "guard event {Guard} could not be saved -- the request itself is not affected", guardId);
            return false;
        }
    }
}
