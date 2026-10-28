using SI.Management.Web.Data;

namespace SI.Management.Web.Jobs;

/// The pipeline as the Pro database keeps it: what the definition table says (HasTable false = the schema is older than #269).
public sealed record StoredFlow(bool HasTable, string? Mode, FlowDefinition? Definition);

/// <summary>
/// The pipeline's definition (cfg.JobFlow, written by Operations > Jobs, read by the runner), its run records (cfg.FlowRun +
/// cfg.FlowStepRun, written by the runner), and (#306) the install's run lock and queue (cfg.PipelineLock / cfg.PipelineQueue):
/// Run now on the pipeline, a stage or a step is a QUEUED request the runner takes when the install is free. Every change of
/// the definition is a cfg.ChangeLog row (Scope 'job', Name 'flow') in the same transaction (job.change.set).
/// </summary>
public interface IFlowStore
{
    Task<StoredFlow> ReadAsync(CancellationToken ct);
    /// "Saved" | "Missing" (no cfg.JobFlow yet).
    Task<string> SaveAsync(string mode, FlowDefinition definition, string by, string reason, CancellationToken ct);
    Task<FlowRun?> LastRunAsync(CancellationToken ct);
    /// #306: each job's newest step record of the last 30 days (the last status / duration per step, whatever run it was in).
    Task<IReadOnlyList<FlowStepRun>> LastStepRunsAsync(CancellationToken ct);
    /// #306: a Run now into the queue. Outcome: "Queued" | "Deduplicated" (the same request already waits) | "Missing" (no queue table yet).
    Task<(long Id, string Outcome)> EnqueueAsync(string scope, string target, string by, CancellationToken ct);
    /// #306: a waiting request taken out of the queue; false when it is no longer waiting (it started, or is gone).
    Task<bool> CancelAsync(long id, string by, CancellationToken ct);
    /// #306: the requests waiting or running (oldest first), and who holds the lock now.
    Task<(IReadOnlyList<PipelineRequest> Queue, PipelineLock? Lock)> QueueAsync(CancellationToken ct);
    /// #700: the RUNNING run cancelled -- marked Cancelled with who and why (never resumed), its queue request ended and the
    /// install's lock released at once, in one transaction. Its job executions are stopped by the runner (started next).
    Task<RunCancel> CancelRunAsync(string flowRunId, string by, string reason, CancellationToken ct);
}

public sealed class SqlFlowStore : IFlowStore
{
    public const string ReadSql = """
IF OBJECT_ID(N'cfg.JobFlow') IS NULL
    SELECT 0 AS HasTable, CAST(NULL AS nvarchar(16)) AS Mode, CAST(NULL AS nvarchar(max)) AS DefinitionJson;
ELSE
    SELECT 1 AS HasTable, f.Mode, f.DefinitionJson FROM (SELECT 1 AS One) AS o LEFT JOIN cfg.JobFlow AS f ON f.FlowId = N'daily';
""";

    public const string SaveSql = """
IF OBJECT_ID(N'cfg.JobFlow') IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT DefinitionJson FROM cfg.JobFlow WITH (UPDLOCK, HOLDLOCK) WHERE FlowId = N'daily');
MERGE cfg.JobFlow AS t
USING (SELECT N'daily' AS FlowId) AS s ON t.FlowId = s.FlowId
WHEN MATCHED THEN UPDATE SET Mode = @Mode, DefinitionJson = @Json, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHEN NOT MATCHED THEN INSERT (FlowId, Mode, DefinitionJson, UpdatedBy) VALUES (N'daily', @Mode, @Json, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'flow', N'job', N'flow', N'Set', @old, @Json, @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// SELECT *: Scope / Target / RequestedBy (#306) exist once the schema is applied again (it only adds).
    public const string LastRunSql = """
IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL
SELECT TOP (1) * FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC;
""";

    public const string StepsSql = """
SELECT * FROM cfg.FlowStepRun WHERE FlowRunId = @FlowRunId ORDER BY StepOrder;
""";

    public const string LastStepsSql = """
IF OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL
SELECT x.* FROM (
    SELECT s.*, ROW_NUMBER() OVER (PARTITION BY s.Job ORDER BY r.StartedUtc DESC, s.StepOrder DESC) AS Rn
    FROM cfg.FlowStepRun AS s JOIN cfg.FlowRun AS r ON r.FlowRunId = s.FlowRunId
    WHERE r.FlowId = N'daily' AND r.StartedUtc > DATEADD(day, -30, SYSUTCDATETIME())
      AND s.State NOT IN (N'Waiting', N'Disabled') AND (s.ErrorClass IS NULL OR s.ErrorClass <> N'before-rerun')
) AS x WHERE x.Rn = 1;
""";

    public const string EnqueueSql = """
IF OBJECT_ID(N'cfg.PipelineQueue') IS NULL BEGIN SELECT CAST(0 AS bigint) AS Id, N'Missing' AS Outcome; RETURN; END
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @id bigint = (SELECT TOP (1) Id FROM cfg.PipelineQueue WITH (UPDLOCK, HOLDLOCK) WHERE PipelineId = N'daily' AND Scope = @Scope AND Target = @Target AND State = N'Queued' ORDER BY Id);
IF @id IS NOT NULL BEGIN COMMIT; SELECT @id AS Id, N'Deduplicated' AS Outcome; RETURN; END
INSERT cfg.PipelineQueue (PipelineId, Scope, Target, Trg, RequestedBy) VALUES (N'daily', @Scope, @Target, N'manual', @By);
SET @id = CAST(SCOPE_IDENTITY() AS bigint);
COMMIT;
SELECT @id AS Id, N'Queued' AS Outcome;
""";

    public const string CancelSql = """
IF OBJECT_ID(N'cfg.PipelineQueue') IS NULL BEGIN SELECT 0 AS Cancelled; RETURN; END
UPDATE cfg.PipelineQueue SET State = N'Cancelled', CancelledBy = @By, EndedUtc = SYSUTCDATETIME() WHERE Id = @Id AND State = N'Queued';
SELECT @@ROWCOUNT AS Cancelled;
""";

    public const string QueueSql = """
IF OBJECT_ID(N'cfg.PipelineQueue') IS NOT NULL
SELECT N'q' AS Kind, Id, Scope, Target, Trg, RequestedBy, RequestedUtc, State, Note, CAST(NULL AS nvarchar(128)) AS Holder, CAST(NULL AS nvarchar(200)) AS What, CAST(NULL AS datetime2) AS HeartbeatUtc
FROM cfg.PipelineQueue WHERE PipelineId = N'daily' AND State IN (N'Queued', N'Running')
UNION ALL
SELECT N'l', 0, N'', N'', N'', NULL, NULL, N'', NULL, Holder, What, HeartbeatUtc FROM cfg.PipelineLock WHERE LockId = N'install' AND Holder IS NOT NULL
ORDER BY Kind, Id;
""";

    /// #700: cancel the RUNNING run in one transaction -- the run (Cancelled, who, why, the end), its queue request (Done,
    /// Outcome Cancelled) and the lock held for it (released). A run that has ended is left as it is. The web identity writes
    /// it ONLY through cfg.FlowRunCancelSet (sql/si-pro-settings.sql: one run, never the table -- it holds no right on
    /// cfg.FlowRun, cfg.PipelineLock or cfg.PipelineQueue for this). A database without the procedure yet answers Missing.
    public const string CancelRunSql = """
IF OBJECT_ID(N'cfg.FlowRunCancelSet') IS NULL BEGIN SELECT N'Missing' AS Outcome, CAST(NULL AS nvarchar(128)) AS Holder, 0 AS Running; RETURN; END
EXEC cfg.FlowRunCancelSet @FlowRunId = @FlowRunId, @By = @By, @Why = @Why;
""";

    private readonly ISqlExecutor _sql;
    /// #302 (AUDIT-1.1): the runner's scheduled runs name who last set the pipeline (Kind 'flow', target jobflow/daily).
    private readonly SI.Management.Web.Audit.IChangeAttributionWriter? _attribution;
    public SqlFlowStore(ISqlExecutor sql, SI.Management.Web.Audit.IChangeAttributionWriter? attribution = null) { _sql = sql; _attribution = attribution; }

    private static DateTimeOffset? Utc(SqlRow r, string c) => r.Date(c) is { } d ? new DateTimeOffset(DateTime.SpecifyKind(d, DateTimeKind.Utc)) : null;
    private static Dictionary<string, object?> None => new();

    public async Task<StoredFlow> ReadAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ReadSql, None, ct);
        var r = rows.FirstOrDefault();
        if (r is null || r.Long("HasTable") != 1) return new(false, null, null);
        var json = r.Str("DefinitionJson");
        return new(true, r.Str("Mode"), string.IsNullOrWhiteSpace(json) ? null : JobFlow.FromJson(json));
    }

    public async Task<string> SaveAsync(string mode, FlowDefinition definition, string by, string reason, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(SaveSql, new Dictionary<string, object?>
        {
            ["Mode"] = mode, ["Json"] = JobFlow.ToJson(definition with { Mode = mode }), ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = reason.Length > 400 ? reason[..400] : reason,
        }, ct);
        var outcome = rows.FirstOrDefault()?.Str("Outcome") ?? "Saved";
        if (outcome == "Saved" && _attribution is not null)
            await _attribution.RecordAsync(SI.Management.Web.Audit.ChangeAttribution.CorrelationId(),
                [new SI.Management.Web.Audit.AttributionEntry("jobflow/daily", by, SI.Management.Web.Audit.AttributionKinds.Flow) { Title = reason }], ct);
        return outcome;
    }

    private static FlowStepRun Step(SqlRow s) => new((int)(s.Long("StepOrder") ?? 0), (int)(s.Long("GroupNo") ?? 0), s.Str("Job") ?? "", s.Str("State") ?? "", s.Str("Execution"),
        Utc(s, "StartedUtc"), Utc(s, "EndedUtc"), s.Str("ErrorClass"), s.Str("Error"),
        // SELECT *: a database whose schema was not applied again has no Attempts / RetryReason / Stage -- they stay null
        s.Long("Attempts") is { } at ? (int)at : null, s.Str("RetryReason"), s.Str("Stage"));

    public async Task<FlowRun?> LastRunAsync(CancellationToken ct)
    {
        var r = (await _sql.QueryAsync(LastRunSql, None, ct)).FirstOrDefault();
        if (r?.Str("FlowRunId") is not { Length: > 0 } id) return null;
        var steps = (await _sql.QueryAsync(StepsSql, new Dictionary<string, object?> { ["FlowRunId"] = id }, ct)).Select(Step).ToList();
        return new FlowRun(id, r.Str("Trg") ?? "", r.Str("FromStep"), r.Str("State") ?? "", Utc(r, "StartedUtc") ?? DateTimeOffset.MinValue, Utc(r, "EndedUtc"),
            Utc(r, "HeartbeatUtc"), r.Str("StopReason"), Utc(r, "SlotUtc"), r.Str("Note"), steps,
            r.Str("Scope") is { Length: > 0 } sc ? sc : "pipeline", r.Str("Target"), r.Str("RequestedBy"), r.Str("CancelledBy"), r.Str("Version"));
    }

    public async Task<RunCancel> CancelRunAsync(string flowRunId, string by, string reason, CancellationToken ct)
    {
        var who = string.IsNullOrWhiteSpace(by) ? "someone" : by.Trim();
        var why = $"cancelled by {who}: {reason.Trim()}";
        var r = (await _sql.QueryAsync(CancelRunSql, new Dictionary<string, object?>
        {
            ["FlowRunId"] = flowRunId, ["By"] = who.Length > 256 ? who[..256] : who, ["Why"] = why.Length > 1000 ? why[..1000] : why,
        }, ct)).FirstOrDefault();
        return new RunCancel(r?.Str("Outcome") ?? "Missing", r?.Str("Holder"), (int)(r?.Long("Running") ?? 0));
    }

    public async Task<IReadOnlyList<FlowStepRun>> LastStepRunsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(LastStepsSql, None, ct)).Select(Step).ToList();

    public async Task<(long Id, string Outcome)> EnqueueAsync(string scope, string target, string by, CancellationToken ct)
    {
        if (!JobFlow.Scopes.Contains(scope)) throw new ArgumentException($"'{scope}' is not pipeline, stage, step or from-step");
        var r = (await _sql.QueryAsync(EnqueueSql, new Dictionary<string, object?>
        {
            ["Scope"] = scope, ["Target"] = scope == "pipeline" ? "" : target, ["By"] = by.Length > 256 ? by[..256] : by,
        }, ct)).FirstOrDefault();
        return (r?.Long("Id") ?? 0, r?.Str("Outcome") ?? "Missing");
    }

    public async Task<bool> CancelAsync(long id, string by, CancellationToken ct) =>
        ((await _sql.QueryAsync(CancelSql, new Dictionary<string, object?> { ["Id"] = id, ["By"] = by.Length > 256 ? by[..256] : by }, ct)).FirstOrDefault()?.Long("Cancelled") ?? 0) > 0;

    public async Task<(IReadOnlyList<PipelineRequest> Queue, PipelineLock? Lock)> QueueAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(QueueSql, None, ct);
        var q = rows.Where(r => r.Str("Kind") == "q").Select(r => new PipelineRequest(r.Long("Id") ?? 0, r.Str("Scope") ?? "", r.Str("Target") ?? "", r.Str("Trg") ?? "",
            r.Str("RequestedBy"), Utc(r, "RequestedUtc"), r.Str("State") ?? "", r.Str("Note"))).ToList();
        var l = rows.FirstOrDefault(r => r.Str("Kind") == "l") is { } lr ? new PipelineLock(lr.Str("Holder") ?? "", lr.Str("What"), Utc(lr, "HeartbeatUtc")) : null;
        return (q, l);
    }
}
