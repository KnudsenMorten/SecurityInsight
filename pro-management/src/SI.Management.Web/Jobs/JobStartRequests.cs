using System.Text.Json.Nodes;

namespace SI.Management.Web.Jobs;

/// #931 (Azure Container Apps: a job start that carries containers / initContainers -- empty arrays included -- needs
/// Microsoft.App/jobs/write besides jobs/start/action). The web app must not hold jobs/write: it would let it change a job's
/// image, command and identity. So a start with values NEVER sends a template: the values become a 'start-env' row in
/// cfg.JobTriggerRequest, the job is started with no body, and the row is bound to the execution the start returned (or
/// closed as failed when the start failed, so no later execution runs a start the person was told did not happen). The
/// job's entrypoint claims the row bound to its own execution and sets only the names allowed for that job
/// (engine/_shared/SI-JobStartRequest.ps1). A database without the start-env columns (one schema behind) starts the old way.
public sealed class StartRequestJobsClient : IJobsClient
{
    public const string Insert = """
INSERT INTO cfg.JobTriggerRequest (JobName, Action, EnvJson, RequestedBy) OUTPUT inserted.RequestId VALUES (@Job, N'start-env', @Env, @By);
""";
    public const string Bind = "UPDATE cfg.JobTriggerRequest SET ExecutionName = @Exec WHERE RequestId = @Id AND AppliedUtc IS NULL AND ExecutionName IS NULL;";
    public const string Failed = "UPDATE cfg.JobTriggerRequest SET AppliedUtc = SYSUTCDATETIME(), Outcome = N'failed', Detail = @Detail WHERE RequestId = @Id AND AppliedUtc IS NULL;";

    private readonly IJobsClient _inner;
    private readonly SI.Management.Web.Data.ISqlExecutor _sql;

    public StartRequestJobsClient(IJobsClient inner, SI.Management.Web.Data.ISqlExecutor sql) { _inner = inner; _sql = sql; }

    public bool IsConfigured => _inner.IsConfigured;
    public IReadOnlyList<string> RequestedTriggerChanges => _inner.RequestedTriggerChanges;
    public Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct) => _inner.ListAsync(ct);
    public Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct) => _inner.ExecutionsAsync(job, top, ct);
    public Task<string> StartAsync(string job, CancellationToken ct) => _inner.StartAsync(job, ct);
    public Task SetCronAsync(string job, string cron, CancellationToken ct) => _inner.SetCronAsync(job, cron, ct);
    public Task DisableAsync(string job, CancellationToken ct) => _inner.DisableAsync(job, ct);
    public Task EnableAsync(string job, CancellationToken ct) => _inner.EnableAsync(job, ct);
    public Task ScheduleAsync(string job, string cron, CancellationToken ct) => _inner.ScheduleAsync(job, cron, ct);

    public async Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct)
    {
        if (env.Count == 0) return await _inner.StartAsync(job, ct);
        var name = JobRules.Name(job);
        var json = EnvJson(env);
        long id;
        try
        {
            var by = SI.Management.Web.Audit.AuditScope.Current?.Actor is { Length: > 0 } a ? a : "web app";
            var rows = await _sql.QueryAsync(Insert, new Dictionary<string, object?> { ["Job"] = name, ["Env"] = json, ["By"] = by.Length > 256 ? by[..256] : by }, ct);
            id = rows.Count > 0 && rows[0].Long("RequestId") is { } r ? r : throw new InvalidOperationException("the start request was not written");
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not ArgumentException)
        {
            // a database one schema behind (no start-env yet): the start carries its values the old way
            return await _inner.StartWithEnvAsync(job, env, ct);
        }
        string exec;
        try { exec = await _inner.StartAsync(job, ct); }
        catch (Exception ex)
        {
            try { await _sql.QueryAsync(Failed, new Dictionary<string, object?> { ["Id"] = id, ["Detail"] = Short("the start failed: " + ex.Message) }, CancellationToken.None); }
            catch (Exception) { /* the row expires on its own; no execution is bound to it */ }
            throw;
        }
        // the job is running: a bind that fails leaves it running as configured (the row expires), never a failed start
        try { await _sql.QueryAsync(Bind, new Dictionary<string, object?> { ["Id"] = id, ["Exec"] = exec }, CancellationToken.None); }
        catch (Exception) { }
        return exec;
    }

    /// PURE. The values as one JSON object (names checked as the old start body checked them), at most 4000 characters.
    public static string EnvJson(IReadOnlyDictionary<string, string> env)
    {
        var o = new JsonObject();
        foreach (var kv in env.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            if (!JobRules.EnvName().IsMatch(kv.Key)) throw new ArgumentException($"'{kv.Key}' is not an environment variable name");
            o[kv.Key] = kv.Value;
        }
        var s = o.ToJsonString();
        return s.Length <= 4000 ? s : throw new ArgumentException("the start's values are too long");
    }

    private static string Short(string s) => s.Length > 1000 ? s[..1000] : s;
}
