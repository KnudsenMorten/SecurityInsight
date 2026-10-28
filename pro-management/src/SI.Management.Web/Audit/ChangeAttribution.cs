using SI.Management.Web.Data;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Audit;

/// <summary>
/// #302 (framework AUDIT-1.1): WHO ASKED FOR A CHANGE THAT A JOB CARRIES OUT. When the web app hands work to a job -- a
/// staged change committed, a setting saved, an exemption request approved, a held close set released, a job or the flow
/// started now -- it records, AT COMMIT, one row per changed target in cfg.ChangeAttribution: the request's correlation id
/// (the same id as its audit event and its change rows), the stored row's key, the person who initiated it and the
/// approver when an approval applied. The job's audit writer (engine\pro-settings\SI-Audit.ps1) reads it and writes
/// Actor = that person, After.appliedBy = the job, After.jobRun, After.approvedBy, CorrelationId = this id. Keyed by the
/// target, so a removed row is still attributed after it is gone.
/// </summary>
public static class AttributionKinds
{
    /// Put in force by the jobs' settings layer at their next run (settings.change.apply).
    public const string Change = "change";
    /// A job execution a person started (its environment carries SI_AUDIT_CID).
    public const string Start = "start";
    /// A held vulnerability close set released (guard.release.apply).
    public const string Release = "release";
    /// The job flow's definition changed (a scheduled flow run names who set it).
    public const string Flow = "flow";
}

public static class AttributionOps
{
    public const string Set = "set";
    public const string Remove = "remove";
    public const string Start = "start";
    public const string Approve = "approve";
}

/// One changed target: who initiated it, who approved it (null = no approval applied).
public sealed record AttributionEntry(string TargetKey, string Actor, string Kind = AttributionKinds.Change, string Op = AttributionOps.Set)
{
    public string? ApprovedBy { get; init; }
    public string? Title { get; init; }
}

public interface IChangeAttributionWriter
{
    /// Records the entries under <paramref name="correlationId"/>. Never throws (except cancellation): a failure is logged
    /// and counted in <see cref="AuditHealth"/> -- the change itself already happened. Returns the rows written.
    Task<int> RecordAsync(string correlationId, IEnumerable<AttributionEntry> entries, CancellationToken ct);
}

/// <summary>THE web writer of cfg.ChangeAttribution: one guarded INSERT per entry (the jobs' PowerShell writer has the same text).</summary>
public sealed class SqlChangeAttributionWriter : IChangeAttributionWriter
{
    public const string InsertSql = """
IF OBJECT_ID(N'cfg.ChangeAttribution') IS NULL
    SELECT N'Missing' AS Outcome;
ELSE
BEGIN
    INSERT cfg.ChangeAttribution (CorrelationId, TargetKey, Kind, Op, Title, Actor, ApprovedBy, Source)
    VALUES (@CorrelationId, @TargetKey, @Kind, @Op, @Title, @Actor, @ApprovedBy, @Source);
    SELECT N'Saved' AS Outcome;
END
""";

    private readonly ISqlExecutor _sql;
    private readonly AuditHealth _health;
    private readonly ILogger<SqlChangeAttributionWriter> _log;

    public SqlChangeAttributionWriter(ISqlExecutor sql, AuditHealth health, ILogger<SqlChangeAttributionWriter> log) { _sql = sql; _health = health; _log = log; }

    public static IReadOnlyDictionary<string, object?> Parameters(string correlationId, AttributionEntry e, string source = "web") => new Dictionary<string, object?>
    {
        ["CorrelationId"] = Cut(correlationId, 64),
        ["TargetKey"] = Cut(e.TargetKey, 400),
        ["Kind"] = e.Kind,
        ["Op"] = e.Op,
        ["Title"] = Cut(AuditRedaction.Text(e.Title), 400),
        ["Actor"] = Cut(e.Actor, 256),
        ["ApprovedBy"] = string.IsNullOrWhiteSpace(e.ApprovedBy) ? null : Cut(e.ApprovedBy, 256),
        ["Source"] = source,
    };

    private static string? Cut(string? s, int n) => s is null ? null : s.Length > n ? s[..n] : s;

    public async Task<int> RecordAsync(string correlationId, IEnumerable<AttributionEntry> entries, CancellationToken ct)
    {
        var n = 0;
        foreach (var e in entries)
        {
            if (string.IsNullOrWhiteSpace(e.TargetKey) || string.IsNullOrWhiteSpace(e.Actor)) continue;
            try
            {
                var rows = await _sql.QueryAsync(InsertSql, Parameters(correlationId, e), ct);
                if (rows.FirstOrDefault()?.Str("Outcome") == "Missing")
                {
                    _health.Fail("the Pro database has no cfg.ChangeAttribution yet -- apply sql\\si-pro-settings.sql (it only adds)");
                    _log.LogWarning("who asked for {Target} not recorded: cfg.ChangeAttribution does not exist yet", e.TargetKey);
                    return n;
                }
                n++;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _health.Fail(ex.Message);
                _log.LogError(ex, "who asked for {Target} ({Actor}) could not be recorded", e.TargetKey, e.Actor);
            }
        }
        return n;
    }
}

/// The request's side of the attribution: its correlation id, whether a person made it, and the job environment.
public static class ChangeAttribution
{
    /// The environment of a job execution a person started: the request's correlation id (cfg.ChangeAttribution's row)
    /// and the person, the fallback when the job cannot read the store.
    public const string CidEnv = "SI_AUDIT_CID";
    public const string StartedByEnv = "SI_AUDIT_STARTED_BY";

    /// The correlation id of the ambient request (= the commit id of its audit event and change rows), else a new one.
    public static string CorrelationId(AuditScope? scope = null) => (scope ?? AuditScope.Current)?.CorrelationId ?? Guid.NewGuid().ToString("N");

    /// A signed-in person made the request (an Entra user or a sign-in-link session), not an anonymous call.
    public static bool IsPerson(AuditScope? s) =>
        s is not null && !string.IsNullOrWhiteSpace(s.Actor) && s.Actor != "anonymous" && s.ActorSource is AuditSources.Web or AuditSources.Portal;

    /// The variables a job started for this person carries; empty when no person is behind the request.
    public static IReadOnlyDictionary<string, string> JobEnv(AuditScope? s) => IsPerson(s)
        ? new Dictionary<string, string>(StringComparer.Ordinal) { [CidEnv] = s!.CorrelationId, [StartedByEnv] = s.Actor.Length > 200 ? s.Actor[..200] : s.Actor }
        : new Dictionary<string, string>(StringComparer.Ordinal);
}

/// <summary>
/// Every job the web app starts for a person (Run now, Run flow now, re-run from a step, a template release, a released
/// close set, the mail job after a request) carries who started it: the attribution row is written under the request's
/// correlation id BEFORE the start, and the execution's environment gets SI_AUDIT_CID / SI_AUDIT_STARTED_BY. A start
/// without a person behind it (a background step) is passed through unchanged.
/// </summary>
public sealed class AttributedJobsClient : IJobsClient
{
    private readonly IJobsClient _inner;
    private readonly IChangeAttributionWriter _attribution;
    public AttributedJobsClient(IJobsClient inner, IChangeAttributionWriter attribution) { _inner = inner; _attribution = attribution; }

    public bool IsConfigured => _inner.IsConfigured;
    public Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct) => _inner.ListAsync(ct);
    public Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct) => _inner.ExecutionsAsync(job, top, ct);
    public Task SetCronAsync(string job, string cron, CancellationToken ct) => _inner.SetCronAsync(job, cron, ct);
    public Task DisableAsync(string job, CancellationToken ct) => _inner.DisableAsync(job, ct);
    public Task EnableAsync(string job, CancellationToken ct) => _inner.EnableAsync(job, ct);
    public Task ScheduleAsync(string job, string cron, CancellationToken ct) => _inner.ScheduleAsync(job, cron, ct);

    public async Task<string> StartAsync(string job, CancellationToken ct)
    {
        var env = await PrepareAsync(job, null, ct);
        return env.Count == 0 ? await _inner.StartAsync(job, ct) : await _inner.StartWithEnvAsync(job, env, ct);
    }

    public async Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct) =>
        await _inner.StartWithEnvAsync(job, await PrepareAsync(job, env, ct), ct);

    private async Task<IReadOnlyDictionary<string, string>> PrepareAsync(string job, IReadOnlyDictionary<string, string>? env, CancellationToken ct)
    {
        var scope = AuditScope.Current;
        var extra = ChangeAttribution.JobEnv(scope);
        if (extra.Count == 0) return env ?? new Dictionary<string, string>(StringComparer.Ordinal);
        await _attribution.RecordAsync(scope!.CorrelationId,
            [new AttributionEntry("job/" + job, scope.Actor, AttributionKinds.Start, AttributionOps.Start) { Title = $"{job} started by {scope.Actor}" }], ct);
        var merged = new Dictionary<string, string>(env ?? new Dictionary<string, string>(), StringComparer.Ordinal);
        foreach (var (k, v) in extra) merged.TryAdd(k, v);
        return merged;
    }
}
