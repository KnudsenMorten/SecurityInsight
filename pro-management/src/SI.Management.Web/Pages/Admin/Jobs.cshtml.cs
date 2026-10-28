using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Web.Auth;
using SI.Management.Web.Data;
using SI.Management.Web.Export;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// The installation's Container Apps jobs: cadence (cron), enabled or not, run now, the last executions, and the console
/// log of an execution (ContainerAppConsoleLogs in the SI workspace). Every change asks first (confirm dialog), goes to
/// ARM with the web app's managed identity, and is recorded in cfg.ChangeLog (Scope 'job').
/// </summary>
public sealed class JobsModel : PageModel
{
    public const string AuditSql = """
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Name, N'job', N'job', N'Set', @Old, @New, @By, @Reason);
SELECT N'Saved' AS Outcome;
""";

    private readonly IJobsClient _jobs;
    private readonly IConsoleLogReader _logs;
    private readonly ISqlExecutor _sql;
    private readonly ILogger<JobsModel> _log;
    private readonly IFlowStore _flow;

    private readonly IConfiguration? _config;

    public JobsModel(IJobsClient jobs, IConsoleLogReader logs, ISqlExecutor sql, IFlowStore flow, ILogger<JobsModel> log, IConfiguration? config = null)
    { _jobs = jobs; _logs = logs; _sql = sql; _flow = flow; _log = log; _config = config; }

    /// CR5 step 1: the install's own job names (section "Jobs": the updater, the template release job), today's names by default.
    private JobsOptions JobOpts => _config?.GetSection(JobsOptions.Section).Get<JobsOptions>() ?? new JobsOptions();

    /// #306: the pipeline a new install gets: 19:00 in the local time of its Azure region (owner 2026-10-15; the install writes
    /// that start time and zone), or the start time set, read in the install's
    /// time zone (the setting SI_Pipeline_TimeZone) -- what the page shows until a pipeline is stored.
    private FlowDefinition DefaultFlow() => JobFlow.Default(List.Select(j => j.Name), _config?["SI_Pipeline_StartTime"], _config?["SI_Pipeline_TimeZone"]);

    // ---- #306: the queue, the lock, and each step's last outcome ----
    public IReadOnlyList<PipelineRequest> Queue { get; private set; } = Array.Empty<PipelineRequest>();
    public PipelineLock? Lock { get; private set; }
    public IReadOnlyDictionary<string, FlowStepRun> LastSteps { get; private set; } = new Dictionary<string, FlowStepRun>();
    [BindProperty] public string? Stage { get; set; }
    [BindProperty] public string? ToStage { get; set; }
    [BindProperty] public bool StageRunIfPreviousFailed { get; set; }
    [BindProperty] public long RequestId { get; set; }
    [BindProperty] public string? FlowTimeZone { get; set; }

    // ---- #269: the daily job flow (operator 2026-10-04: "make both options, but flow is default/preferred") ----
    /// flow | schedules -- cfg.JobFlow's mode, else what the jobs show (caj-si-flow's wake-up on = flow).
    public string FlowMode { get; private set; } = "schedules";
    public FlowDefinition Flow { get; private set; } = JobFlow.Default(Array.Empty<string>());
    public bool FlowStored { get; private set; }
    public bool FlowTable { get; private set; } = true;
    public FlowRun? LastFlowRun { get; private set; }
    public bool FlowJobPresent => List.Any(j => j.Name == JobFlow.FlowJob);
    /// ?preview=flow|schedules -- what switching would do, before anything changes.
    [BindProperty(SupportsGet = true)] public string? Preview { get; set; }
    public IReadOnlyList<FlowSwitchRow> PreviewRows { get; private set; } = Array.Empty<FlowSwitchRow>();
    public int? StepOf(string jobName) { var i = Flow.Steps.ToList().FindIndex(s => s.Job == JobSchedule.Key(jobName)); return i < 0 ? null : i + 1; }

    [BindProperty] public string? Step { get; set; }
    [BindProperty] public string? Direction { get; set; }
    [BindProperty] public bool StepEnabled { get; set; } = true;
    [BindProperty] public bool StepWithPrevious { get; set; }
    [BindProperty] public string? StepOnFailure { get; set; }
    [BindProperty] public int StepTimeout { get; set; } = 240;
    [BindProperty] public string? FlowCadence { get; set; }
    [BindProperty] public string? FlowStartTime { get; set; }
    [BindProperty] public int FlowWeekday { get; set; } = 1;
    [BindProperty] public int FlowIntervalHours { get; set; } = 6;
    [BindProperty] public int FlowIntervalMinutes { get; set; }
    /// leaving the pipeline: 'schedule' (its own timer -- the remembered one, else the default) or 'manual'
    [BindProperty] public string? LeaveAs { get; set; }
    [BindProperty] public string? SwitchTo { get; set; }

    private async Task LoadFlowAsync(CancellationToken ct)
    {
        try
        {
            var stored = await _flow.ReadAsync(ct);
            FlowTable = stored.HasTable;
            FlowStored = stored.Definition is not null;
            Flow = stored.Definition ?? DefaultFlow();
            FlowMode = stored.Mode is "flow" or "schedules" ? stored.Mode : JobFlow.InferMode(List);
            // the stored mode column is the truth; the JSON's copy only travels with it
            Flow = Flow with { Mode = FlowMode };
            LastFlowRun = await _flow.LastRunAsync(ct);
            try
            {
                LastSteps = (await _flow.LastStepRunsAsync(ct)).GroupBy(s => s.Job).ToDictionary(g => g.Key, g => g.First());
                (Queue, Lock) = await _flow.QueueAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "reading the pipeline queue failed (apply the Pro database schema again)"); }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the job flow failed");
            Flow = DefaultFlow();
            FlowMode = JobFlow.InferMode(List);
        }
        if (Preview is "flow" or "schedules") PreviewRows = JobFlow.SwitchPlan(List, Preview, Flow);
    }

    [BindProperty(SupportsGet = true)] public string? Job { get; set; }
    [BindProperty(SupportsGet = true)] public string? Execution { get; set; }
    [BindProperty(SupportsGet = true)] public string? Contains { get; set; }
    [BindProperty] public string? Cron { get; set; }

    public bool Configured => _jobs.IsConfigured;
    public IReadOnlyList<JobInfo> List { get; private set; } = Array.Empty<JobInfo>();
    public IReadOnlyList<JobExecution> Executions { get; private set; } = Array.Empty<JobExecution>();
    public QueryResult<IReadOnlyList<ConsoleLine>>? Log { get; private set; }
    public string? Error { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!Configured) return;
        try
        {
            List = await _jobs.ListAsync(ct);
            await LoadFlowAsync(ct);
            if (Job is not null && List.Any(j => j.Name == Job))
            {
                Executions = await _jobs.ExecutionsAsync(Job, 15, ct);
                if (Execution is not null || Executions.Count > 0)
                    Log = await _logs.ReadAsync(Job, Execution ?? Executions[0].Name, 24 * 7, 500, Contains, ct);
            }
        }
        catch (ArgumentException ex) { Error = ex.Message; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the jobs failed");
            Error = "The jobs could not be read: " + ex.Message;
        }
    }

    /// Excel workbook of the jobs and their last executions: the selected job's, or every job's when none is selected.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        await OnGetAsync(ct);
        var executions = new List<(string Job, JobExecution E)>();
        if (Configured && Error is null)
        {
            try
            {
                if (Job is not null && List.Any(j => j.Name == Job)) executions.AddRange(Executions.Select(e => (Job, e)));
                else foreach (var j in List) executions.AddRange((await _jobs.ExecutionsAsync(j.Name, 15, ct)).Select(e => (j.Name, e)));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "reading the job executions failed");
                Error = "The executions could not be read: " + ex.Message;
            }
        }
        return await ExcelExport.FileAsync("jobs", null, (x, info) =>
        {
            info.Filter("Job", Job);
            if (!Configured) info.Notes.Add(NotConfiguredJobsClient.Why);
            if (Error is not null) info.Notes.Add(Error);
            var now = DateTimeOffset.UtcNow;
            x.Sheet(info, "Jobs", new[] { "Job", "Name", "What it does", "Needs first", "State", "When", "Next run (UTC)", "Schedule (cron, UTC)", "Schedule while disabled (cron, UTC)", "Image", "Provisioning" },
                List.Select(j =>
                {
                    var d = SI.Management.Web.Jobs.JobSchedule.Describe(j.Cron ?? j.DisabledCron, now);
                    var role = SI.Management.Web.Jobs.JobSchedule.Role(j.Name);
                    return new object?[]
                    {
                        SI.Management.Web.Jobs.JobSchedule.Label(j.Name), j.Name, role?.Does,
                        role is null ? null : string.Join(", ", role.Needs.Select(n => SI.Management.Web.Jobs.JobSchedule.Label("caj-si-" + n))),
                        j.Enabled ? "enabled" : j.Disabled ? "disabled" : j.TriggerType.ToLowerInvariant(), d.Cadence,
                        j.Enabled && d.NextUtc is { } nx ? nx.UtcDateTime : null, j.Cron, j.DisabledCron, j.Image, j.ProvisioningState,
                    };
                }));
            x.Sheet(info, "Executions", new[] { "Job", "Execution", "Status", "Started", "Ended", "Duration (min)" },
                executions.Select(p => new object?[]
                {
                    p.Job, p.E.Name, p.E.Status, p.E.StartTime, p.E.EndTime,
                    p.E.StartTime is { } a && p.E.EndTime is { } b ? Math.Round((b - a).TotalMinutes, 2) : null,
                }));
            return Task.CompletedTask;
        }, ct);
    }

    [SI.Management.Web.Audit.Audited("job.execution.start")]
    public Task<IActionResult> OnPostRunAsync(CancellationToken ct) => Act("run now", async j =>
    {
        // #306: a step of the pipeline runs through the queue (never beside a run that is going); any other job starts at once
        await LoadFlowAsync(ct);
        if (FlowMode == "flow" && StepOf(j) is not null && List.Any(x => x.Name == JobFlow.FlowJob)) return await QueueRun("step", JobSchedule.Key(j), ct);
        // a job that is already running is not started a second time beside itself: it says so and starts nothing
        if (!JobRules.RunsSideBySide(j) && JobRules.RunningExecution(await _jobs.ExecutionsAsync(j, 15, ct)) is { } live) return JobRules.AlreadyRunningText(live);
        return "execution " + await _jobs.StartAsync(j, ct);
    }, ct);
    [SI.Management.Web.Audit.Audited("job.schedule.disable")]
    public Task<IActionResult> OnPostDisableAsync(CancellationToken ct) => Act("disable", async j => { await _jobs.DisableAsync(j, ct); return "disabled (manual trigger; the schedule is remembered)"; }, ct);
    [SI.Management.Web.Audit.Audited("job.schedule.enable")]
    public Task<IActionResult> OnPostEnableAsync(CancellationToken ct) => Act("enable", async j => { await _jobs.EnableAsync(j, ct); return "enabled (schedule restored)"; }, ct);
    // the schedule editor's fields (a blank Cron = build it from these; Cron set = the advanced field, as before)
    [BindProperty] public string? Often { get; set; }
    [BindProperty] public string? StartTime { get; set; }
    [BindProperty] public int Weekday { get; set; } = 1;
    [BindProperty] public int DayOfMonth { get; set; } = 1;
    [BindProperty] public int EveryHours { get; set; } = 6;

    [SI.Management.Web.Audit.Audited("job.schedule.change")]
    public Task<IActionResult> OnPostCronAsync(CancellationToken ct) => Act("change schedule", async j =>
    {
        var raw = !string.IsNullOrWhiteSpace(Often) ? SI.Management.Web.Jobs.JobSchedule.ToCron(Often, StartTime, Weekday, DayOfMonth, EveryHours, Cron) : Cron;
        var cron = JobRules.CronOf(raw ?? "");
        await _jobs.SetCronAsync(j, cron, ct);
        return "schedule " + cron;
    }, ct);

    // ---- #269: the pipeline's handlers. Every one asks first (confirm dialog), is Admin, and is on the audit trail. ----
    // ---- #306: Run now on the pipeline, a stage or a step. Each is a request in the install's queue: it starts as soon as
    // nothing else runs (the install's ONE lock), never over another run. The runner is started at once to take it. ----
    // The queueing itself is PipelineRequests.QueueAsync -- shared with Operations > Data quality's Re-run from here.
    private Task<string> QueueRun(string scope, string target, CancellationToken ct) =>
        PipelineRequests.QueueAsync(_flow, _jobs, scope, target, User.ChangeName(), Lock, ct);

    [SI.Management.Web.Audit.Audited("job.flow.start")]
    public Task<IActionResult> OnPostFlowRunAsync(CancellationToken ct) => FlowAct("run the pipeline now", async () =>
        (null, await QueueRun("pipeline", "", ct)), ct, needsFlowJob: true);

    [SI.Management.Web.Audit.Audited("job.flow.start")]
    public Task<IActionResult> OnPostFlowRerunAsync(CancellationToken ct) => FlowAct("re-run the pipeline from a step", async () =>
    {
        var step = JobSchedule.Key(Step ?? "");
        if (!Flow.Steps.Any(s => s.Job == step)) throw new ArgumentException($"{Step} is not a step of the pipeline");
        return (null, await QueueRun("from-step", step, ct) + "; the steps above it do not run");
    }, ct, needsFlowJob: true);

    [SI.Management.Web.Audit.Audited("job.flow.start")]
    public Task<IActionResult> OnPostStageRunAsync(CancellationToken ct) => FlowAct("run a stage now", async () =>
    {
        var stage = (Stage ?? "").Trim().ToLowerInvariant();
        if (!Flow.StageList.Any(s => s.Id == stage)) throw new ArgumentException($"'{Stage}' is not a stage of the pipeline");
        return (null, await QueueRun("stage", stage, ct));
    }, ct, needsFlowJob: true);

    [SI.Management.Web.Audit.Audited("job.flow.start")]
    public Task<IActionResult> OnPostStepRunAsync(CancellationToken ct) => FlowAct("run a step now", async () =>
    {
        var step = JobSchedule.Key(Step ?? "");
        if (!Flow.Steps.Any(s => s.Job == step)) throw new ArgumentException($"{Step} is not a step of the pipeline");
        return (null, await QueueRun("step", step, ct));
    }, ct, needsFlowJob: true, lifecycleJob: JobSchedule.Key(Step ?? "") == "updater" ? JobOpts.UpdaterJobName : null);

    [SI.Management.Web.Audit.Audited("job.flow.cancel")]
    public Task<IActionResult> OnPostQueueCancelAsync(CancellationToken ct) => FlowAct("take a request out of the queue", async () =>
    {
        var ok = await _flow.CancelAsync(RequestId, User.ChangeName(), ct);
        if (!ok) throw new InvalidOperationException($"request {RequestId} is no longer waiting (it started or is gone)");
        return (null, $"request {RequestId} was taken out of the queue");
    }, ct);

    // ---- #700: cancel the RUNNING pipeline run (owner 2026-10-15: "why not kill it"). Admin, confirm dialog with a reason,
    // on the audit trail. In the database at once (one transaction): the run is Cancelled with who and why -- the scheduler
    // never resumes it -- its queue request ends and the install's lock is released, so the next queued request starts on
    // the next wake-up. Then the runner is started once (SI_FLOW_CANCEL=1) to stop the run's job executions and the runner
    // that held the lock, over Azure, with the jobs' own identity. No SQL by people. ----
    [BindProperty] public string? FlowRunId { get; set; }
    [BindProperty] public string? CancelReason { get; set; }

    [SI.Management.Web.Audit.Audited("job.flowrun.cancel")]
    public Task<IActionResult> OnPostRunCancelAsync(CancellationToken ct) => FlowAct("cancel the running pipeline run", async () =>
    {
        var reason = (CancelReason ?? "").Trim();
        if (reason.Length == 0) throw new ArgumentException("say why the run is cancelled (it is kept with the run and on the audit trail)");
        if (reason.Length > 400) reason = reason[..400];
        var id = (FlowRunId ?? "").Trim();
        if (id.Length == 0) id = LastFlowRun?.FlowRunId ?? "";
        if (id.Length == 0 || LastFlowRun is null || LastFlowRun.FlowRunId != id) throw new InvalidOperationException("that run is not the pipeline's last run any more -- nothing was cancelled");
        var by = User.ChangeName();
        var r = await _flow.CancelRunAsync(id, by, reason, ct);
        switch (r.Outcome)
        {
            case "Missing": throw new InvalidOperationException("the Pro database has no pipeline runs yet -- apply the Pro database schema again (it only adds), then try again");
            case "NotFound": throw new InvalidOperationException("that run is not in the database -- nothing was cancelled");
            case "NotRunning": throw new InvalidOperationException("that run has already ended -- nothing was cancelled");
        }
        var env = new Dictionary<string, string> { ["SI_FLOW_CANCEL"] = "1", ["SI_FLOW_CANCEL_RUN"] = id, ["SI_FLOW_CANCEL_REASON"] = reason, ["SI_FLOW_TRIGGER"] = "manual" };
        if (!string.IsNullOrEmpty(r.Holder)) env["SI_FLOW_CANCEL_RUNNER"] = r.Holder!;
        string stopped;
        try { stopped = $"; its running jobs are being stopped (runner execution {await _jobs.StartWithEnvAsync(JobFlow.FlowJob, env, ct)})"; }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException)
        {
            // the run IS cancelled (never resumed, the lock is free); only the stop of its executions did not start
            _log.LogError(ex, "starting the runner to stop the cancelled run's jobs failed");
            stopped = $"; its running jobs could NOT be asked to stop ({ex.Message}) -- cancel again to retry";
        }
        return (null, $"the pipeline run was cancelled and will not be resumed; the next run can start now{stopped}");
    }, ct, needsFlowJob: true);

    [SI.Management.Web.Audit.Audited("job.flow.change")]
    public Task<IActionResult> OnPostFlowStageAsync(CancellationToken ct) => FlowAct("move a step to another stage", () =>
        Task.FromResult<(FlowDefinition?, string)>((JobFlow.MoveToStage(Flow, JobSchedule.Key(Step ?? ""), (ToStage ?? "").Trim().ToLowerInvariant()),
            $"{JobSchedule.Label(Step ?? "")} is now in {JobFlow.StageName((ToStage ?? "").Trim().ToLowerInvariant())}")), ct);

    [SI.Management.Web.Audit.Audited("job.flow.change")]
    public Task<IActionResult> OnPostStageSettingsAsync(CancellationToken ct) => FlowAct("change a stage", () =>
    {
        var stage = (Stage ?? "").Trim().ToLowerInvariant();
        return Task.FromResult<(FlowDefinition?, string)>((JobFlow.WithStage(Flow, stage, StageRunIfPreviousFailed),
            StageRunIfPreviousFailed ? $"{JobFlow.StageName(stage)} starts even when the stage before it did not succeed" + (stage == "deliver" ? " (never after a failed Collect)" : "")
                                     : $"{JobFlow.StageName(stage)} starts only when the stage before it succeeded"));
    }, ct);

    [SI.Management.Web.Audit.Audited("job.flow.change")]
    public Task<IActionResult> OnPostFlowMoveAsync(CancellationToken ct) => FlowAct("move a step", () =>
        Task.FromResult<(FlowDefinition?, string)>((JobFlow.Move(Flow, JobSchedule.Key(Step ?? ""), Direction == "up" ? -1 : 1), $"{JobSchedule.Label(Step ?? "")} moved {(Direction == "up" ? "up" : "down")}")), ct);

    [SI.Management.Web.Audit.Audited("job.flow.change")]
    public Task<IActionResult> OnPostFlowStepAsync(CancellationToken ct) => FlowAct("change a step", () =>
        Task.FromResult<(FlowDefinition?, string)>((JobFlow.Update(Flow, JobSchedule.Key(Step ?? ""), StepEnabled, StepWithPrevious, (StepOnFailure ?? "skip-dependents").ToLowerInvariant(), StepTimeout),
            $"{JobSchedule.Label(Step ?? "")} saved")), ct);

    [SI.Management.Web.Audit.Audited("job.flow.change")]
    public Task<IActionResult> OnPostFlowCadenceAsync(CancellationToken ct) => FlowAct("change when the pipeline runs", () =>
    {
        var minutes = FlowIntervalMinutes > 0 ? FlowIntervalMinutes : FlowIntervalHours * 60;
        var d = JobFlow.WithCadence(Flow, FlowCadence ?? "daily", FlowStartTime, FlowWeekday, minutes, FlowTimeZone);
        return Task.FromResult<(FlowDefinition?, string)>((d, "the pipeline runs " + JobFlow.CadenceText(d)));
    }, ct);

    [SI.Management.Web.Audit.Audited("job.flow.change")]
    public Task<IActionResult> OnPostFlowIncludeAsync(CancellationToken ct) => FlowAct("add a job to the pipeline", async () =>
    {
        var job = List.FirstOrDefault(j => j.Name == Job) ?? throw new ArgumentException($"'{Job}' is not one of this installation's jobs");
        var d = JobFlow.Include(Flow, job.Name);
        // in the pipeline a job has no timer of its own: its timer is remembered (as Disable does), and comes back when it leaves
        if (FlowMode == "flow" && job.Enabled) await _jobs.DisableAsync(job.Name, ct);
        return (d, $"{JobSchedule.Label(job.Name)} is now step {d.Steps.ToList().FindIndex(s => s.Job == JobSchedule.Key(job.Name)) + 1} of the pipeline" + (FlowMode == "flow" && job.Enabled ? $" (its own timer {job.Cron} is remembered)" : ""));
    }, ct, lifecycleJob: Job);

    [SI.Management.Web.Audit.Audited("job.flow.change")]
    public Task<IActionResult> OnPostFlowRemoveAsync(CancellationToken ct) => FlowAct("take a job out of the pipeline", async () =>
    {
        var job = List.FirstOrDefault(j => j.Name == Job) ?? throw new ArgumentException($"'{Job}' is not one of this installation's jobs");
        var d = JobFlow.Remove(Flow, job.Name);
        var how = "it starts only when started";
        if (FlowMode == "flow" && !job.Enabled && LeaveAs == "schedule")
        {
            if (job.DisabledCron is { Length: > 0 } rc) { await _jobs.EnableAsync(job.Name, ct); how = $"it runs on its own timer again ({JobSchedule.Describe(rc, DateTimeOffset.UtcNow).Cadence})"; }
            else { var c = JobFlow.DefaultCron.TryGetValue(JobSchedule.Key(job.Name), out var dc) ? dc : "0 4 * * *"; await _jobs.ScheduleAsync(job.Name, c, ct); how = $"it runs on its own timer ({JobSchedule.Describe(c, DateTimeOffset.UtcNow).Cadence})"; }
        }
        return (d, $"{JobSchedule.Label(job.Name)} left the pipeline -- {how}");
    }, ct, lifecycleJob: Job);

    /// Flow <-> schedules, as previewed: every job's trigger per JobFlow.SwitchPlan, then the mode is stored.
    [SI.Management.Web.Audit.Audited("job.flow.mode")]
    public Task<IActionResult> OnPostFlowModeAsync(CancellationToken ct) => FlowAct("switch how the jobs run", async () =>
    {
        var to = SwitchTo is "flow" or "schedules" ? SwitchTo : throw new ArgumentException("choose the pipeline or schedules");
        if (to == "flow" && !FlowJobPresent) throw new InvalidOperationException($"this installation has no {JobFlow.FlowJob} job yet -- run setup (Bootstrap) once to create it, then switch");
        var plan = JobFlow.SwitchPlan(List, to, Flow);
        if (plan.Any(p => p.Action != "keep" && AccessLifecycle.IsLifecycleJob(p.Job, JobOpts)) && !User.IsSuperAdmin())
            throw new UnauthorizedAccessException("the switch moves the updater -- that needs SuperAdmin");
        var done = 0; var failed = new List<string>();
        // timers ON first, then off: a switch stopped half-way leaves both on -- never "neither mode" (nothing scheduled)
        foreach (var p in plan.Where(p => p.Action != "keep").OrderBy(p => p.Action == "to-manual" ? 1 : 0))
        {
            try
            {
                var j = List.First(x => x.Name == p.Job);
                if (p.Action == "to-manual") await _jobs.DisableAsync(p.Job, ct);
                else if (j.DisabledCron is { Length: > 0 } rc && rc == p.Cron) await _jobs.EnableAsync(p.Job, ct);
                else await _jobs.ScheduleAsync(p.Job, p.Cron!, ct);
                done++;
            }
            catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or ArgumentException) { failed.Add($"{p.Job}: {ex.Message}"); }
        }
        if (failed.Count > 0) throw new InvalidOperationException($"{done} job(s) switched, {failed.Count} not: {string.Join("; ", failed)} -- switch again (it only changes what is left)");
        return (Flow with { Mode = to }, to == "flow" ? $"the jobs run as one pipeline ({JobFlow.CadenceText(Flow).ToLowerInvariant()}); {done} job(s) changed" : $"every job runs on its own timer again; {done} job(s) changed");
    }, ct);

    private async Task<IActionResult> FlowAct(string what, Func<Task<(FlowDefinition? Def, string Message)>> action, CancellationToken ct, bool needsFlowJob = false, string? lifecycleJob = null)
    {
        if (!User.IsAdmin()) return Forbid();
        if (lifecycleJob is not null && AccessLifecycle.IsLifecycleJob(lifecycleJob, JobOpts) && !User.IsSuperAdmin())
            return AccessResults.Refused(Request, AccessDecision.No($"{lifecycleJob} runs the install's updates / template releases -- that needs SuperAdmin"));
        try
        {
            if (!Configured) throw new InvalidOperationException(NotConfiguredJobsClient.Why);
            List = await _jobs.ListAsync(ct);
            await LoadFlowAsync(ct);
            if (needsFlowJob && !FlowJobPresent) throw new InvalidOperationException($"this installation has no {JobFlow.FlowJob} job -- run setup (Bootstrap) once to create it");
            var before = JobFlow.ToJson(Flow with { Mode = FlowMode });
            var (def, message) = await action();
            var saved = "";
            if (def is not null)
            {
                var (problems, warnings) = JobFlow.Validate(def);
                if (problems.Length > 0) throw new ArgumentException(problems[0]);
                var outcome = await _flow.SaveAsync(def.Mode is "flow" or "schedules" ? def.Mode : FlowMode, def, User.ChangeName(), what, ct);
                if (outcome == "Missing") throw new InvalidOperationException("the Pro database has no cfg.JobFlow yet -- apply the Pro database schema again (it only adds), then try again");
                if (warnings.Length > 0) saved = " Note: " + warnings[0] + ".";
            }
            else await AuditAsync(JobFlow.FlowJob, what, before, message, ct);
            TempData["toast"] = message + RequestedTriggerJobsClient.Note(_jobs.RequestedTriggerChanges) + "." + saved;
            TempData["toastKind"] = saved.Length > 0 ? "warn" : "ok";
        }
        catch (UnauthorizedAccessException ex) { return AccessResults.Refused(Request, AccessDecision.No(ex.Message)); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or HttpRequestException)
        {
            _log.LogError(ex, "flow action {What} failed", what);
            TempData["toast"] = $"The pipeline: {what} failed -- {ex.Message}";
            TempData["toastKind"] = "error";
        }
        return RedirectToPage(new { job = (string?)null });
    }

    private async Task<IActionResult> Act(string what, Func<string, Task<string>> action, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var job = Job ?? "";
        // the updater and the template release job are the install's lifecycle: SuperAdmin (#253)
        if (AccessLifecycle.IsLifecycleJob(job, JobOpts) && !User.IsSuperAdmin())
            return AccessResults.Refused(Request, AccessDecision.No($"{job} runs the install's updates / template releases -- that needs SuperAdmin"));
        try
        {
            JobRules.Name(job);
            List = await _jobs.ListAsync(ct);
            var before = List.FirstOrDefault(j => j.Name == job) ?? throw new ArgumentException($"'{job}' is not one of this installation's jobs");
            // #269: a job of the pipeline has no timer of its own -- giving it one would start it beside the pipeline
            if (what is "enable" or "change schedule")
            {
                await LoadFlowAsync(ct);
                if (FlowMode == "flow" && StepOf(job) is { } n)
                    throw new InvalidOperationException($"it is step {n} of the pipeline and has no timer of its own -- take it out of the pipeline first (it then gets its own schedule)");
            }
            var result = await action(job);
            var audited = await AuditAsync(job, what, $"{before.TriggerType} {before.Cron ?? before.DisabledCron}", result, ct);
            TempData["toast"] = $"{job}: {result}{RequestedTriggerJobsClient.Note(_jobs.RequestedTriggerChanges)}." + (audited ? "" : " (The change log row could not be written -- see the application log.)");
            TempData["toastKind"] = audited ? "ok" : "warn";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or HttpRequestException)
        {
            _log.LogError(ex, "job action {What} on {Job} failed", what, job);
            TempData["toast"] = $"{job}: {what} failed -- {ex.Message}";
            TempData["toastKind"] = "error";
        }
        return RedirectToPage(new { job });
    }

    private async Task<bool> AuditAsync(string job, string what, string old, string @new, CancellationToken ct)
    {
        try
        {
            var by = User.ChangeName();
            await _sql.QueryAsync(AuditSql, new Dictionary<string, object?>
            {
                ["Name"] = job, ["Old"] = old, ["New"] = @new, ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = what,
            }, ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "auditing job action {What} on {Job} failed", what, job);
            return false;
        }
    }

    public static string StateClass(string status) => status.ToLowerInvariant() switch
    {
        "succeeded" => "ok",
        "failed" or "degraded" or "stopped" => "bad",
        _ => "run",
    };
}
