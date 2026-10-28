namespace SI.Management.Web.Jobs;

/// CR8 (framework DOCS/REQUIREMENTS.md 12.11f item 1, SI #659): the web app with START-ONLY rights on the jobs
/// (Container Apps Jobs Operator on the named jobs, Jobs Reader on the resource group -- Jobs:ChangeMode = request). It can
/// list, start and stop jobs, but never change one: a change of a job's TRIGGER (Disable, Enable, Change schedule, the
/// pipeline's include / remove / switch) becomes a row in cfg.JobTriggerRequest, and the pipeline runner (caj-si-flow, as
/// its own identity) applies it -- the trigger and the tags only, read back -- on the wake-up this client starts at once
/// (else within its 5-minute timer). Every other call goes to the inner client unchanged.
/// The same checks as the direct change run here first, so a request that cannot be applied is refused on the page.
public sealed class RequestedTriggerJobsClient : IJobsClient
{
    public const string Insert = """
INSERT INTO cfg.JobTriggerRequest (JobName, Action, Cron, RequestedBy) VALUES (@Job, @Action, @Cron, @By);
SELECT CAST(SCOPE_IDENTITY() AS BIGINT) AS RequestId;
""";

    private readonly IJobsClient _inner;
    private readonly SI.Management.Web.Data.ISqlExecutor _sql;
    private readonly List<string> _requested = new();

    public RequestedTriggerJobsClient(IJobsClient inner, SI.Management.Web.Data.ISqlExecutor sql) { _inner = inner; _sql = sql; }

    public bool IsConfigured => _inner.IsConfigured;
    public IReadOnlyList<string> RequestedTriggerChanges => _requested;
    public Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct) => _inner.ListAsync(ct);
    public Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct) => _inner.ExecutionsAsync(job, top, ct);
    public Task<string> StartAsync(string job, CancellationToken ct) => _inner.StartAsync(job, ct);
    public Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct) => _inner.StartWithEnvAsync(job, env, ct);

    public async Task SetCronAsync(string job, string cron, CancellationToken ct)
    {
        var j = await JobAsync(job, ct);
        if (!j.TriggerType.Equals("Schedule", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("only a scheduled job has a schedule -- enable it first");
        await RequestAsync(j.Name, "to-schedule", JobRules.CronOf(cron), ct);
    }

    public async Task DisableAsync(string job, CancellationToken ct)
    {
        var j = await JobAsync(job, ct);
        if (!j.TriggerType.Equals("Schedule", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("only a scheduled job can be disabled");
        await RequestAsync(j.Name, "to-manual", null, ct);
    }

    public async Task EnableAsync(string job, CancellationToken ct)
    {
        var j = await JobAsync(job, ct);
        if (j.DisabledCron is not { Length: > 0 }) throw new InvalidOperationException("this job was not disabled here: it has no remembered schedule -- set one with 'Change schedule'");
        await RequestAsync(j.Name, "to-schedule", null, ct);
    }

    public async Task ScheduleAsync(string job, string cron, CancellationToken ct)
    {
        var j = await JobAsync(job, ct);
        if (j.TriggerType.Equals("Event", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("an event-triggered job is started by its queue -- it has no schedule");
        await RequestAsync(j.Name, "to-schedule", JobRules.CronOf(cron), ct);
    }

    private async Task<JobInfo> JobAsync(string job, CancellationToken ct)
    {
        JobRules.Name(job);
        return (await _inner.ListAsync(ct)).FirstOrDefault(j => j.Name == job) ?? throw new ArgumentException($"'{job}' is not one of this installation's jobs");
    }

    private async Task RequestAsync(string job, string action, string? cron, CancellationToken ct)
    {
        var by = SI.Management.Web.Audit.AuditScope.Current?.Actor is { Length: > 0 } a ? a : "web app";
        var rows = await _sql.QueryAsync(Insert, new Dictionary<string, object?>
        {
            ["Job"] = job, ["Action"] = action, ["Cron"] = cron, ["By"] = by.Length > 256 ? by[..256] : by,
        }, ct);
        _requested.Add($"{job} {action}{(cron is null ? "" : " " + cron)}");
        // the runner takes it now (a plain start -- start-only rights suffice); a start refused or a runner already busy
        // leaves the request waiting for the runner's own timer, never lost
        try { await _inner.StartAsync(JobFlow.FlowJob, ct); } catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or ArgumentException) { }
        _ = rows;
    }

    /// PURE. What the page adds to its message after a change that was requested, not made.
    public static string Note(IReadOnlyList<string> requested) => requested.Count == 0 ? "" :
        $" -- requested ({requested.Count}): the pipeline job applies it within a few minutes; the job list shows it once applied";
}
