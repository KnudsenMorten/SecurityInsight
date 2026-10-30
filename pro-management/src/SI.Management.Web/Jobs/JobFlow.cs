using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SI.Management.Web.Jobs;

/// One step of the pipeline: a job, whether it runs, whether it starts together with the step above, what a failure does,
/// how long it may run, and (#306) the stage it belongs to. The same JSON the PowerShell runner reads
/// (engine\_shared\SI-JobFlow.ps1).
public sealed record FlowStep(string Job, bool Enabled = true, bool WithPrevious = false, string OnFailure = "skip-dependents", int TimeoutMinutes = 240, string Stage = "");

/// #306: one stage of the pipeline -- collect | correlate | deliver | custom-&lt;name&gt; -- and whether it starts when the
/// stage before it did not succeed (never for Deliver after a failed Collect).
public sealed record FlowStage(string Id, string Name, bool RunIfPreviousFailed = false);

/// The install's ONE pipeline (#269, #306): its mode (flow | schedules), when it starts (the start time is a wall-clock time
/// in TimeZone -- "UTC" for a schedule stored before time zones), and its steps in order, each with its stage. Stages is the
/// stage order (null = derived from the steps).
public sealed record FlowDefinition(string Mode, string StartTime, string Cadence, int Weekday, int IntervalMinutes, IReadOnlyList<FlowStep> Steps,
    IReadOnlyList<FlowStage>? Stages = null, string TimeZone = "UTC", string Name = "Daily pipeline")
{
    /// The stages in order (the stored list, else from the steps).
    public IReadOnlyList<FlowStage> StageList => Stages is { Count: > 0 } s ? s
        : Steps.Select(x => string.IsNullOrEmpty(x.Stage) ? "collect" : x.Stage).Distinct().Select(JobFlow.NewStage).ToList();
    /// True when the stored definition was the older one-list form (read as a pipeline, saved as one on the next change).
    public bool Migrated { get; init; }
    public IReadOnlyList<string> MigrationNotes { get; init; } = Array.Empty<string>();
    /// The shipped default LAYOUT the pipeline has been brought to (JobFlow.ConvergeDefaultLayout; the JSON's 'defaults'):
    /// 1 = stored before the layout had levels (every step one after the other).
    public int DefaultsLevel { get; init; } = 1;
}

/// A run as the runner records it (cfg.FlowRun + cfg.FlowStepRun).
/// Attempts / RetryReason: how many times the runner started the step's job, and why it started it again (a container that
/// never ran the engine -- an Azure platform problem -- is started again; a failure of the engine never is). Null on a
/// record written before they were kept. Stage (#306): the stage the step ran in.
public sealed record FlowStepRun(int Order, int Group, string Job, string State, string? Execution, DateTimeOffset? StartedUtc, DateTimeOffset? EndedUtc, string? ErrorClass, string? Error,
    int? Attempts = null, string? RetryReason = null, string? Stage = null);
/// #576: a running execution's progress as the engine writes it (cfg.StepProgress): what it does now, done / total when known.
public sealed record StepProgress(string Execution, string Job, string Phase, long? Done, long? Total, DateTimeOffset? AtUtc);
/// #576: what the pipeline page shows for a running step: the phase, done (of total), a percentage when the total is known,
/// when it was written, and whether that is older than <see cref="JobFlow.ProgressStaleMinutes"/> (shown greyed).
public sealed record StepProgressView(string Phase, long? Done, long? Total, int? Percent, DateTimeOffset? AtUtc, bool Stale);
/// Scope / Target / RequestedBy (#306): what was run -- pipeline | stage | step | from-step -- and who asked for it.
public sealed record FlowRun(string FlowRunId, string Trigger, string? FromStep, string State, DateTimeOffset StartedUtc, DateTimeOffset? EndedUtc,
    DateTimeOffset? HeartbeatUtc, string? StopReason, DateTimeOffset? SlotUtc, string? Note, IReadOnlyList<FlowStepRun> Steps,
    string Scope = "pipeline", string? Target = null, string? RequestedBy = null, string? CancelledBy = null, string? Version = null)
{
    /// #700: a Cancelled run (a person, support, the update) is finished too -- it is never resumed.
    public bool Finished => State is "Succeeded" or "Failed" or "Stopped" or "Cancelled";
}

/// #700: what cancelling the running pipeline run did in the database. Outcome: "Cancelled" | "NotRunning" (it has ended)
/// | "NotFound" | "Missing" (no run table yet). Holder: the runner that held the install's lock for the run (released at
/// once); Running: how many of its steps were running (the runner is started to stop them).
public sealed record RunCancel(string Outcome, string? Holder, int Running);

/// One request waiting for (or holding) the install's run lock (cfg.PipelineQueue).
public sealed record PipelineRequest(long Id, string Scope, string Target, string Trigger, string? RequestedBy, DateTimeOffset? RequestedUtc, string State, string? Note);

/// Who holds the install's run lock now (cfg.PipelineLock); null = nobody.
public sealed record PipelineLock(string Holder, string? What, DateTimeOffset? HeartbeatUtc);

/// One row of a mode switch's preview: what happens to a job.
public sealed record FlowSwitchRow(string Job, string Action, string? Cron, string Why);

/// <summary>
/// The daily pipeline (#269, #306; operator 2026-10-05: "one flow ... flows/subflows ... run subflows individually (run
/// now) ... appoint schedules to flows"; naming: a flow is a PIPELINE, a subflow a STAGE, the stages Collect -> Correlate
/// -> Deliver). Pure: the dependency map + the default pipeline (the SAME as config\job-flow.locked.json -- JobFlowTests
/// compares them), schema 2 and the migration of a schema-1 flow, the edits the Jobs page makes, the schedule in words in
/// its time zone (SCHED-1.4), when it runs next (SCHED-1.1) and the preview of a mode switch. Nothing here talks to ARM or SQL.
/// </summary>
public static class JobFlow
{
    public const string FlowJob = "caj-si-flow";
    /// The runner's cron only WAKES it; the runner starts the pipeline when it is due (SCHED-1.1).
    public const string TickCron = "*/5 * * * *";
    public static readonly string[] OnFailureChoices = ["skip-dependents", "stop", "continue"];
    public static readonly string[] Cadences = ["daily", "weekdays", "weekly", "interval"];
    public static readonly string[] Scopes = ["pipeline", "stage", "step", "from-step"];

    /// The shipped default: 19:00 in the local time of the install's Azure region, after the 18:30 update, so the night's run
    /// is done the next morning (owner 2026-10-21: "move the start time for all si jobs to 7pm on all sites"). A new install
    /// writes 19:00 with its region's zone (SI_Pipeline_StartTime + SI_Pipeline_TimeZone; setup\_shared\SI-NightlySchedule.ps1
    /// moves an existing install once). A start time that is SET is read in SI_Pipeline_TimeZone; with no start time set the
    /// default keeps DefaultTimeZone (Danish time: the region is not known).
    public const string DefaultStartTime = "19:00";
    public const string DefaultTimeZone = "Europe/Copenhagen";
    public const string DefaultName = "Daily pipeline";

    public static readonly string[] StageIds = ["collect", "correlate", "deliver"];
    public static string StageName(string id) => id switch { "collect" => "Collect", "correlate" => "Correlate", "deliver" => "Deliver", _ => id };
    public static FlowStage NewStage(string id) => new(id, StageName(id));

    /// The stage as a HEADING and in the overview: its name plus what the stage is for, in the owner's words (2026-10-13) --
    /// "Collect (data-in)", "Correlate (data structure)", "Deliver (data-out)". The same three as config\job-flow.locked.json
    /// ('title') and Get-SIPipelineStageTitle. Decided from the stage ID, so an install whose STORED pipeline carries the
    /// name from before ("Collect") shows the new words without anything being rewritten. storedName: a name a person gave
    /// the stage themselves is kept as it is; a custom stage shows its own name (else its id). A sentence about one step
    /// keeps the short name (StageName).
    public static string StageTitle(string id, string? storedName = null)
    {
        var k = (id ?? "").Trim().ToLowerInvariant();
        var n = (storedName ?? "").Trim();
        var title = k switch { "collect" => "Collect (data-in)", "correlate" => "Correlate (data structure)", "deliver" => "Deliver (data-out)", _ => null };
        if (title is null) return n.Length > 0 ? n : id ?? "";
        return n.Length == 0 || n.Equals(StageName(k), StringComparison.OrdinalIgnoreCase) || n.Equals(title, StringComparison.OrdinalIgnoreCase) || n.Equals(k, StringComparison.OrdinalIgnoreCase) ? title : n;
    }
    public static string StageTitle(FlowStage stage) => StageTitle(stage.Id, stage.Name);
    /// Inside Deliver the targets are independent: a failed vulnerability connector does not skip the data sync or the mail.
    public static string StageOnFailure(string stage) => stage == "deliver" ? "continue" : "skip-dependents";
    public static bool IsStageId(string id) => System.Text.RegularExpressions.Regex.IsMatch(id ?? "", @"^(collect|correlate|deliver|custom(-[a-z0-9]{1,24})?)$");

    /// The Daily pipeline: each stage strictly one step after the other; a job not installed is left out.
    public static readonly (string Stage, string[] Jobs)[] DefaultStages =
    [
        ("collect", ["ptc", "identity", "azure", "endpoint", "publicip"]),
        ("correlate", ["asset-correlation", "risk-analysis", "risk-analysis-detailed"]),
        ("deliver", ["asset-cmdb-sql", "asset-cmdb", "asset-vulnerabilities", "asset-vulns-servicenow", "asset-datasync", "close-loop-mail", "verification"]),
    ];

    /// The steps of a default stage that start together with the step above them (config\job-flow.locked.json defaultPipeline
    /// 'withPrevious'): azure and endpoint run side by side after identity -- neither reads the other's output of the same day;
    /// #754: Risk Analysis Summary and Detailed run side by side after the asset correlation -- neither reads the other's output.
    public static readonly IReadOnlyDictionary<string, string[]> DefaultTogether = new Dictionary<string, string[]> { ["collect"] = ["endpoint"], ["correlate"] = ["risk-analysis-detailed"] };

    /// The layout level each DefaultTogether step came with (config\job-flow.locked.json 'withPreviousSince'): a stored pipeline
    /// still on the default layout of ITS level is brought to the current one (ConvergeDefaultLayout).
    public static readonly IReadOnlyDictionary<string, int> TogetherSince = new Dictionary<string, int> { ["endpoint"] = 2, ["risk-analysis-detailed"] = 3 };

    /// The current default layout level (SI-JobFlow.ps1 $script:SIJobFlow.DefaultsLevel): 2 = endpoint with azure, 3 (#754) =
    /// Risk Analysis Detailed with Risk Analysis Summary too, 4 (#636) = Risk Analysis Summary off by default.
    public const int CurrentDefaultsLevel = 4;

    /// #636 (owner 2026-10-19: "i prefer to switch so detailed becomes the engine default and summary is optional"): the steps
    /// a new pipeline has switched OFF (config\job-flow.locked.json 'defaultEnabled': false) -- Risk Analysis Summary. Every
    /// Summary-shaped view is a grouping of the Detailed findings; the step's own on/off switch stays.
    public static readonly IReadOnlySet<string> DefaultOff = new HashSet<string>(StringComparer.Ordinal) { "risk-analysis" };
    /// The layout level that switched them off on a stored pipeline still the default of its level with every step on.
    public const int SummaryOffSince = 4;
    public static string SummaryOffNote(string job) =>
        $"{job} is now switched off (the new default: the Summary report is optional -- every Summary view is a grouping of the Detailed findings) -- to run it again, switch the step on and save";
    public static string SummaryKeptNote(string job) =>
        $"{job} stays switched on: the pipeline was changed by a person -- the Summary report is optional now (every Summary view is a grouping of the Detailed findings); switch the step off on {SI.Management.Web.Navigation.NavModel.PathOf("/Admin/Jobs")} when nobody reads its mail";

    /// #748: a step every pipeline has (config\job-flow.locked.json 'required'): the verification service runs the daily data
    /// health check (CR2). The update adds it to a stored pipeline without it where its job is installed; the Jobs page does not
    /// remove it -- its off switch is the setting SI_DataHealth_Enabled.
    public static bool Required(string key) => JobSchedule.Key(key) == "verification";
    public const string RequiredWhy = "every pipeline runs it -- it runs the daily data health check; switch the check off with the setting SI_DataHealth_Enabled";

    /// The same order flattened (config\job-flow.locked.json defaultFlow).
    public static readonly string[] DefaultOrder = DefaultStages.SelectMany(s => s.Jobs).ToArray();

    /// The stage each job belongs to (config\job-flow.locked.json 'stage'); '' for a job the map does not know.
    public static string StageOf(string key) => JobSchedule.Key(key) switch
    {
        "ptc" or "identity" or "azure" or "endpoint" or "publicip" => "collect",
        "asset-correlation" or "risk-analysis" or "risk-analysis-detailed" or "asset-trend" => "correlate",
        "asset-cmdb-sql" or "asset-cmdb" or "asset-vulnerabilities" or "asset-vulns-servicenow" or "asset-datasync" or "close-loop-mail" or "verification" or "asset-tagging" => "deliver",
        _ => "",
    };

    /// Each job's own timer in schedules mode (Bootstrap's defaults): what leaving the pipeline / switching to schedules
    /// gives a job with no remembered timer -- the dependency order of the shipped schedule.
    public static readonly IReadOnlyDictionary<string, string> DefaultCron = new Dictionary<string, string>
    {
        ["updater"] = UpdaterCron, ["ptc"] = "0 1 * * *", ["identity"] = "30 4 * * *", ["azure"] = "0 5 * * *", ["endpoint"] = "0 4 * * *",
        ["publicip"] = "15 5 * * *", ["asset-correlation"] = "30 5 * * *", ["asset-cmdb-sql"] = "55 5 * * *", ["asset-cmdb"] = "0 7 * * *",
        ["risk-analysis"] = "0 6 * * *", ["risk-analysis-detailed"] = "0 8 * * *", ["asset-trend"] = "0 9 * * *", ["asset-vulnerabilities"] = "0 10 * * *",
        ["asset-vulns-servicenow"] = "15 10 * * *", ["asset-datasync"] = "30 10 * * *", ["close-loop-mail"] = "45 10 * * *", ["verification"] = "0 11 * * *", ["asset-tagging"] = "50 5 * * *",
        ["schema"] = "0 3 * * 0", ["flow"] = TickCron, ["config-backup"] = "0 18 * * *", ["heartbeat"] = "7,22,37,52 * * * *",
    };

    public static readonly IReadOnlyDictionary<string, int> DefaultTimeout = new Dictionary<string, int> { ["ptc"] = 180 };

    /// Never a step: started on demand (templates), weekly maintenance (schema), the runner itself, the updater (it runs
    /// on its own daily schedule -- OwnSchedule), the daily configuration backup (#404: its own timer, after the working day,
    /// before the pipeline), the hourly status report to Invardia (#718: its own timer, whether or not a pipeline runs) and
    /// a retired job (Retired).
    public static bool NeverInFlow(string key) => key is "templates" or "schema" or "schema-discovery" or "flow" or "config-backup" or "heartbeat" || OwnSchedule(key) || Retired(key);

    /// #412 (operator 2026-10-06, "we dont pull in the same data twice"): asset-properties does nothing any more -- the
    /// endpoint, identity and azure profilers read each source once and publish the full asset metadata themselves. Never a
    /// step and no timer; a stored pipeline loses the step when it is read (config\job-flow.locked.json 'retired',
    /// Test-SIJobFlowRetired).
    public static bool Retired(string key) => JobSchedule.Key(key) == "asset-properties";
    public const string RetiredWhy = "it is retired -- the endpoint, identity and azure profilers read each source once and publish the full asset metadata themselves";

    /// The updater's own timer: 18:30 in the LOCAL time of the install's Azure region (owner 2026-10-21; 23:00 before) -- the
    /// zone's UTC ticks, two with daylight saving (Europe/Amsterdam 16:30 + 17:30 UTC); the updater ends the tick that is not
    /// 18:30 there (setup\_shared\SI-NightlySchedule.ps1, setup\Install-SIUpdaterJob.ps1). This constant is the Danish-time
    /// fallback (a region that is not known).
    public const string UpdaterCron = "30 16,17 * * *";
    public const string UpdaterAt = "18:30";
    /// The earlier Danish-time ticks (23:00) -- what a job without the zone tag was set to before the region step.
    public const string RegionUpdaterCron = "0 21,22 * * *";
    public const string FallbackZone = "Europe/Copenhagen";
    /// The tags the updater job records its zone in: si-nightly-schedule "18:30 &lt;zone&gt;" (or "23:00 &lt;zone&gt;" on a job the
    /// 19:00 move has not reached) and si-nightly-region "&lt;region&gt;" | "unknown".
    public const string NightlyScheduleTag = "si-nightly-schedule";
    public const string NightlyRegionTag = "si-nightly-region";
    public const string OwnScheduleWhy = "the updater runs on its own daily schedule";

    /// The zone the updater job records (tag si-nightly-schedule "23:00 Europe/Amsterdam"); null when it records none.
    public static string? NightlyZone(string? scheduleTag)
    {
        var m = System.Text.RegularExpressions.Regex.Match(scheduleTag ?? "", @"^\s*\d{1,2}:\d{2}\s+(\S+)\s*$");
        return m.Success ? m.Groups[1].Value : null;
    }

    /// The time a schedule tag records ("18:30 Europe/Amsterdam" -> "18:30"); null when it records none.
    public static string? NightlyAt(string? scheduleTag)
    {
        var m = System.Text.RegularExpressions.Regex.Match(scheduleTag ?? "", @"^\s*(\d{1,2}:\d{2})\s+\S+\s*$");
        return m.Success ? m.Groups[1].Value : null;
    }

    /// The UTC cron of at (HH:mm, default 18:30) in zone over a year (every day's time converted) -- the same as
    /// Get-SINightlyUpdaterCron: 18:30 Europe/Amsterdam "30 16,17 * * *"; 23:00 Europe/Amsterdam "0 21,22 * * *",
    /// America/Los_Angeles "0 6,7 * * *", Asia/Tokyo "0 14 * * *"; "" = zone not known.
    public static string UpdaterCronFor(string? zone, int year, string at = UpdaterAt)
    {
        if (string.IsNullOrWhiteSpace(zone) || !TryZone(zone, out var tz)) return "";
        var hm = System.Text.RegularExpressions.Regex.Match(at ?? "", @"^\s*(\d{1,2}):(\d{2})\s*$");
        if (!hm.Success) return "";
        var seen = new SortedDictionary<string, (int H, int M)>(StringComparer.Ordinal);
        for (var d = new DateTime(year, 1, 1, int.Parse(hm.Groups[1].Value, CultureInfo.InvariantCulture), int.Parse(hm.Groups[2].Value, CultureInfo.InvariantCulture), 0, DateTimeKind.Unspecified); d.Year == year; d = d.AddDays(1))
        {
            if (tz.IsInvalidTime(d)) continue;
            var u = TimeZoneInfo.ConvertTimeToUtc(d, tz);
            seen[$"{u.Hour:00}:{u.Minute:00}"] = (u.Hour, u.Minute);
        }
        if (seen.Count == 0) return "";
        var first = seen.Values.First();
        return $"{first.M} {string.Join(",", seen.Values.Select(v => v.H).Distinct().OrderBy(h => h))} * * *";
    }

    /// The updater's timer in plain words (the Jobs page), from what the job records: on its zone's ticks with the zone tag
    /// "Daily at 18:30 local time (Europe/Amsterdam, the install's Azure region)" -- the time the tag records (18:30, or
    /// 23:00 on a job the 19:00 move has not reached); with a region that is not known (tag si-nightly-region "unknown") or no
    /// zone tag on the Danish-time ticks, Danish time. Null = a timer of the customer's own (the page shows the cron in words).
    public static string? UpdaterCadenceText(string? cron, string? scheduleTag, string? regionTag, int? year = null)
    {
        var c = System.Text.RegularExpressions.Regex.Replace((cron ?? "").Trim(), @"\s+", " ");
        if (c.Length == 0) return null;
        var zone = NightlyZone(scheduleTag);
        if (zone is null) return c == UpdaterCron ? $"Daily at {UpdaterAt} Danish time ({FallbackZone})" : c == RegionUpdaterCron ? $"Daily at 23:00 Danish time ({FallbackZone})" : null;
        var at = NightlyAt(scheduleTag) ?? UpdaterAt;
        var y = year ?? DateTime.UtcNow.Year;
        if (c != UpdaterCronFor(zone, y, at)) return null;
        var unknown = string.IsNullOrWhiteSpace(regionTag) || regionTag.Trim().Equals("unknown", StringComparison.OrdinalIgnoreCase);
        if (unknown && zone == FallbackZone) return $"Daily at {at} Danish time ({FallbackZone}; the install's Azure region is not known)";
        return $"Daily at {at} local time ({zone}, the install's Azure region)";
    }

    /// Framework UPDATE-1.6 (a): one updater per environment, daily at 03:00 UTC on its OWN schedule (plus started on a
    /// release) -- never a step of the pipeline, in any mode. It waits while any SI job runs, so as a step of a running
    /// pipeline it waited for itself (found live on ring 1). A switch keeps its timer and gives back one an earlier switch took.
    public static bool OwnSchedule(string key) => JobSchedule.Key(key) == "updater";

    /// #306: not a step, and no timer of its own while the jobs run as a pipeline -- Risk Analysis writes the daily trend
    /// row itself (the job stays runnable by hand).
    public static bool ManualInFlowMode(string key) => JobSchedule.Key(key) == "asset-trend";

    public static string JobName(string key) => "caj-si-" + key;

    /// #576: a progress record older than this is shown greyed ("no update for n min") -- the engine writes at most every 15 s.
    public const int ProgressStaleMinutes = 15;

    /// PURE (#576). The progress of a RUNNING step (Running / Starting, with an execution): the record of its execution, or
    /// null (no record = the page shows "Running" as before). Percent only when the total is known (0..100).
    public static StepProgressView? ProgressOf(FlowStepRun? step, IReadOnlyList<StepProgress>? records, DateTimeOffset now)
    {
        if (step is null || step.State is not ("Running" or "Starting") || string.IsNullOrEmpty(step.Execution) || records is null) return null;
        var r = records.Where(x => string.Equals(x.Execution, step.Execution, StringComparison.OrdinalIgnoreCase)).OrderByDescending(x => x.AtUtc).FirstOrDefault();
        if (r is null || string.IsNullOrWhiteSpace(r.Phase)) return null;
        int? pct = r.Done is { } d && r.Total is { } t && t > 0 ? (int)Math.Clamp(d * 100 / t, 0, 100) : null;
        var stale = r.AtUtc is { } at && (now - at).TotalMinutes > ProgressStaleMinutes;
        return new StepProgressView(r.Phase, r.Done, r.Total, pct, r.AtUtc, stale);
    }

    /// The job whose executions are a step's runs: caj-si-&lt;key&gt;, or the producer of a collection in parts when only that is
    /// installed (the step's recorded execution is the producer's). Null when neither is installed.
    public static string? StepRunJob(string key, IReadOnlyCollection<string> installed)
    {
        var plain = JobName(key);
        if (installed.Contains(plain)) return plain;
        return installed.Contains(plain + "-producer") ? plain + "-producer" : null;
    }

    /// The pipeline page's line for a run of a step's job that the pipeline did not record (it was started outside the
    /// pipeline -- in Azure, by support), when it is newer than the step's own record. Running = it is running now.
    public sealed record OutsideRun(JobExecution Execution, bool Running)
    {
        public string Text => Running ? "running -- started outside the pipeline" : "ran outside the pipeline";
        public string Outcome => Execution.Status.ToLowerInvariant();
    }

    /// PURE. The newest execution of a step's job when the pipeline did not record it and it is newer than the step's record
    /// (-Known: every execution the pipeline's records name). Null when there is nothing to show -- the newest run is the
    /// pipeline's own, older than its record, or no execution was read.
    public static OutsideRun? OutsideRunOf(FlowStepRun? record, IReadOnlyList<JobExecution>? executions, IReadOnlySet<string>? known = null)
    {
        if (executions is null || executions.Count == 0) return null;
        var newest = executions.Where(e => !string.IsNullOrEmpty(e.Name) && e.StartTime is not null).OrderByDescending(e => e.StartTime).FirstOrDefault();
        if (newest is null) return null;
        if (!string.IsNullOrEmpty(record?.Execution) && string.Equals(record.Execution, newest.Name, StringComparison.OrdinalIgnoreCase)) return null;
        if (known is not null && known.Contains(newest.Name)) return null;
        var running = newest.Status is "Running" or "Processing";
        if (record?.StartedUtc is { } recorded) { if (newest.StartTime <= recorded) return null; }
        // no started record to compare with: only a run going NOW is shown (an old ended one says nothing about this step)
        else if (!running) return null;
        return new OutsideRun(newest, running);
    }

    /// The flow view's line for a step that was started more than once ("started 2 times"); null for one start.
    public static string? AttemptText(FlowStepRun? step) => step?.Attempts is > 1 and var n
        ? $"started {n} times" + (step.ErrorClass == "never-started" ? " -- did not start" : "")
        : null;

    /// A step that is RUNNING and that the pipeline found silent: no log line and no record from its job for 2 hours.
    /// A warning only -- the step was left running, nothing was stopped (owner 2026-10-12: "Log + run health + page").
    /// Hours: whole hours of silence when it was noticed; NoticedUtc: when the pipeline noticed it (null on a record
    /// that does not say).
    public sealed record SilentWarning(int Hours, DateTimeOffset? NoticedUtc)
    {
        public string Headline => $"No progress for {Hours} hour{(Hours == 1 ? "" : "s")}";
        public const string Rest = "it is still running and was not stopped";
        public string Text => Headline + " -- " + Rest;
    }

    /// What the runner writes into the step's record when it reports the silence (engine\_shared\SI-JobFlow.ps1,
    /// Get-SIJobFlowSilentText): "... no sign of progress for 2.4 hours (noticed 2026-10-12 08:15 UTC; ...". The two
    /// sides are kept in step by SIv3-JobFlow.Tests.ps1 (this exact pattern) and FlowSilentStepPageTests.
    private static readonly System.Text.RegularExpressions.Regex SilentPattern = new(
        @"no sign of progress for (?<h>\d+(?:\.\d+)?) hours(?: \(noticed (?<t>\d{4}-\d{2}-\d{2} \d{2}:\d{2}) UTC)?",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// The pipeline page's warning for a step: only while the step is still running (it goes when the step ends, and
    /// when the step is started again its record no longer carries the sentence). Null = nothing to show.
    public static SilentWarning? SilentStep(FlowStepRun? step)
    {
        if (step is null || step.State != "Running" || string.IsNullOrEmpty(step.RetryReason)) return null;
        var m = SilentPattern.Match(step.RetryReason);
        if (!m.Success) return null;
        var hours = double.TryParse(m.Groups["h"].Value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var h) ? (int)Math.Floor(h) : 2;
        if (hours < 1) hours = 1;
        DateTimeOffset? noticed = null;
        if (m.Groups["t"].Success && DateTime.TryParseExact(m.Groups["t"].Value, "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
            noticed = new DateTimeOffset(t, TimeSpan.Zero);
        return new SilentWarning(hours, noticed);
    }

    public static FlowDefinition Default(IEnumerable<string> installedJobs, string? startTime = null, string? timeZone = null)
    {
        var have = installedJobs.Select(JobSchedule.Key).ToHashSet(StringComparer.Ordinal);
        var steps = DefaultStages.SelectMany(st => st.Jobs.Where(have.Contains)
            .Select(k => new FlowStep(k, Enabled: !DefaultOff.Contains(k), WithPrevious: TogetherWithShippedAbove(st.Stage, k, have.Contains),
                OnFailure: StageOnFailure(st.Stage), TimeoutMinutes: DefaultTimeout.TryGetValue(k, out var t) ? t : 240, Stage: st.Stage))).ToList();
        var set = startTime is { } s && System.Text.RegularExpressions.Regex.IsMatch(s, @"^([01]\d|2[0-3]):[0-5]\d$");
        // a start time that is set is read in the install's zone; the default time keeps its default zone (19:00 Danish time: no region known here)
        return new FlowDefinition("flow", set ? startTime! : DefaultStartTime, "daily", 1, 1440, steps, DefaultStages.Select(x => NewStage(x.Stage)).ToList(),
            !set || string.IsNullOrWhiteSpace(timeZone) ? DefaultTimeZone : timeZone!.Trim(), DefaultName) { DefaultsLevel = CurrentDefaultsLevel };
    }

    /// <summary>
    /// CONVERGE-DEFAULTS (framework 12.16) for the pipeline's layout -- the same rule as Update-SIJobFlowDefaultLayout: a stored
    /// pipeline below the current level that still has the OLD default layout (no step starts together with another, and each
    /// stage is exactly the shipped stage's steps in the shipped order -- a job not installed is simply absent) gets the
    /// current one: each DefaultTogether step starts together with the step above it; nothing else of a step changes. A
    /// pipeline a person changed is NOT re-laid. Either way the result has the current level, so after a save the decision is
    /// never made again. Changed: Migrated + one MigrationNotes line per step.
    /// </summary>
    /// A DefaultTogether step starts together with the step SHIPPED right above it in its stage -- and only when that step is
    /// there: with it missing the step starts on its own (it would otherwise join a step whose same-day output it reads).
    /// level: the default layout of that level (a step that came with a later level is not together there).
    public static bool TogetherWithShippedAbove(string stage, string job, Func<string, bool> isThere, int level = CurrentDefaultsLevel)
    {
        if (!DefaultTogether.TryGetValue(stage, out var tg) || !tg.Contains(job)) return false;
        if ((TogetherSince.TryGetValue(job, out var since) ? since : 2) > level) return false;
        var jobs = DefaultStages.FirstOrDefault(s => s.Stage == stage).Jobs ?? [];
        var i = Array.IndexOf(jobs, job);
        return i > 0 && isThere(jobs[i - 1]);
    }

    public static FlowDefinition ConvergeDefaultLayout(FlowDefinition d)
    {
        if (d.DefaultsLevel >= CurrentDefaultsLevel) return d;
        var marked = d with { DefaultsLevel = CurrentDefaultsLevel };
        static string St(FlowStep s) => string.IsNullOrEmpty(s.Stage) ? "collect" : s.Stage;
        // level 4 (#636): a pipeline a person changed keeps a DefaultOff step as it is -- one line says so
        var summaryOff = d.DefaultsLevel < SummaryOffSince;
        FlowDefinition Kept()
        {
            if (!summaryOff) return marked;
            var kept = d.Steps.Where(s => DefaultOff.Contains(s.Job) && s.Enabled).Select(s => SummaryKeptNote(s.Job)).ToList();
            return kept.Count == 0 ? marked : marked with { MigrationNotes = d.MigrationNotes.Concat(kept).ToList() };
        }
        var present = d.Steps.Select(s => s.Job).ToHashSet(StringComparer.Ordinal);
        var want = DefaultStages.SelectMany(st => st.Jobs.Where(present.Contains).Select(k => $"{st.Stage}|{k}")).ToList();
        var got = d.Steps.Select(s => $"{St(s)}|{s.Job}").ToList();
        if (!want.SequenceEqual(got)) return Kept();
        // the default of the stored level: a step starts together with the one above it exactly where that level put it
        var level = Math.Max(1, d.DefaultsLevel);
        for (var i = 0; i < d.Steps.Count; i++)
        {
            var was = i > 0 && St(d.Steps[i - 1]) == St(d.Steps[i]) && TogetherWithShippedAbove(St(d.Steps[i]), d.Steps[i].Job, k => k == d.Steps[i - 1].Job, level);
            if (d.Steps[i].WithPrevious != was) return Kept();
        }
        var steps = d.Steps.ToList(); var notes = d.MigrationNotes.ToList(); var changed = false;
        for (var i = 1; i < steps.Count; i++)
        {
            if (steps[i].WithPrevious || St(steps[i - 1]) != St(steps[i]) || !TogetherWithShippedAbove(St(steps[i]), steps[i].Job, k => k == steps[i - 1].Job)) continue;
            steps[i] = steps[i] with { WithPrevious = true }; changed = true;
            notes.Add($"{steps[i].Job} now starts together with {steps[i - 1].Job} (the new default: neither reads the other's output of the same day) -- to run them one after the other again, untick \"start together\" and save");
        }
        if (summaryOff)
        {
            // the default of its level with every step on: the DefaultOff steps are switched off; else they stay, said once
            var allOn = d.Steps.All(s => s.Enabled);
            for (var i = 0; i < steps.Count; i++)
            {
                if (!DefaultOff.Contains(steps[i].Job) || !steps[i].Enabled) continue;
                if (allOn) { steps[i] = steps[i] with { Enabled = false }; changed = true; notes.Add(SummaryOffNote(steps[i].Job)); }
                else notes.Add(SummaryKeptNote(steps[i].Job));
            }
            if (!changed && notes.Count > d.MigrationNotes.Count) return marked with { MigrationNotes = notes };
        }
        return changed ? marked with { Steps = steps, Migrated = true, MigrationNotes = notes } : marked;
    }

    // ---- JSON (camelCase -- the shape the runner and config\job-flow.custom.json use) ----
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false, DefaultIgnoreCondition = JsonIgnoreCondition.Never };

    private sealed record Wire(int Schema, string? Id, string? Name, string? Mode, string? StartTime, string? TimeZone, string? Cadence, int? Weekday, int? IntervalMinutes,
        List<WireStage>? Stages, List<WireStep>? Steps, int? Defaults = null);
    private sealed record WireStage(string? Id, string? Name, bool? RunIfPreviousFailed, List<WireStep>? Steps);
    private sealed record WireStep(string? Job, string? Stage, bool? Enabled, bool? WithPrevious, string? OnFailure, int? TimeoutMinutes);

    /// Schema 2: stages[] (each with its steps) AND the same steps flattened in steps[] (each with its stage), so a reader of
    /// schema 1 (an older runner during the update) still sees the whole pipeline in its order.
    public static string ToJson(FlowDefinition d)
    {
        static WireStep W(FlowStep s) => new(s.Job, string.IsNullOrEmpty(s.Stage) ? "collect" : s.Stage, s.Enabled, s.WithPrevious, s.OnFailure, s.TimeoutMinutes);
        var stages = d.StageList.Select(st => new WireStage(st.Id, st.Name, st.RunIfPreviousFailed, d.Steps.Where(x => (string.IsNullOrEmpty(x.Stage) ? "collect" : x.Stage) == st.Id).Select(W).ToList())).ToList();
        return JsonSerializer.Serialize(new Wire(2, "daily", d.Name, d.Mode, d.StartTime, d.TimeZone, d.Cadence, d.Weekday, d.IntervalMinutes, stages, d.Steps.Select(W).ToList(), Math.Max(1, d.DefaultsLevel)), Json);
    }

    public static FlowDefinition FromJson(string json)
    {
        var w = JsonSerializer.Deserialize<Wire>(json, Json) ?? throw new ArgumentException("not a flow definition");
        var mode = (w.Mode ?? "flow").ToLowerInvariant();
        var cad = (w.Cadence ?? "daily").ToLowerInvariant();
        // a schedule stored before time zones has none: its time was UTC, and stays UTC
        var tz = string.IsNullOrWhiteSpace(w.TimeZone) ? "UTC" : w.TimeZone.Trim();
        static FlowStep R(WireStep s, string stage) => new(JobSchedule.Key(s.Job!), s.Enabled ?? true, s.WithPrevious ?? false, (s.OnFailure ?? StageOnFailure(stage)).ToLowerInvariant(), s.TimeoutMinutes ?? 240, stage);
        if (w.Schema >= 2 && w.Stages is not null)
        {
            var stages = w.Stages.Select(s => (s.Id ?? "custom").ToLowerInvariant()).ToList();
            var steps = w.Stages.SelectMany(s => (s.Steps ?? new()).Where(x => !string.IsNullOrWhiteSpace(x.Job)).Select(x => R(x, (s.Id ?? "custom").ToLowerInvariant()))).ToList();
            return ConvergeDefaultLayout(MoveAfterNeeds(WithoutOwnSchedule(new FlowDefinition(mode, w.StartTime ?? DefaultStartTime, cad, w.Weekday ?? 1, w.IntervalMinutes ?? 1440, steps,
                w.Stages.Select(s => new FlowStage((s.Id ?? "custom").ToLowerInvariant(), s.Name ?? StageName((s.Id ?? "custom").ToLowerInvariant()), s.RunIfPreviousFailed ?? false)).ToList(), tz, w.Name ?? DefaultName)
                { DefaultsLevel = Math.Max(1, w.Defaults ?? 1) })));
        }
        var v1 = (w.Steps ?? new()).Where(s => !string.IsNullOrWhiteSpace(s.Job))
            .Select(s => new FlowStep(JobSchedule.Key(s.Job!), s.Enabled ?? true, s.WithPrevious ?? false, (s.OnFailure ?? "skip-dependents").ToLowerInvariant(), s.TimeoutMinutes ?? 240)).ToList();
        return ConvergeDefaultLayout(MoveAfterNeeds(WithoutOwnSchedule(Migrate(new FlowDefinition(mode, w.StartTime ?? "01:00", cad, w.Weekday ?? 1, w.IntervalMinutes ?? 1440, v1, null, tz)))));
    }

    /// A step runs after every step it NEEDS when that step is in a later STAGE -- the same rule as
    /// Move-SIJobFlowStepAfterNeeds (v3 data model: Risk Analysis now reads the CI build, so a pipeline stored when Risk
    /// Analysis ran in Collect gets it moved to right after the last step it needs, into that step's stage). A misorder
    /// inside one stage is not moved (Validate warns about it); a need that is not a step of the pipeline is ignored. Each
    /// moved step is said in MigrationNotes and the definition is Migrated (the next save stores the new order).
    public static FlowDefinition MoveAfterNeeds(FlowDefinition d)
    {
        static string St(FlowStep s) => string.IsNullOrEmpty(s.Stage) ? "collect" : s.Stage;
        var steps = d.Steps.ToList();
        var moved = new List<string>(); var why = new Dictionary<string, string[]>();
        var changed = true; var guard = 0;
        while (changed && guard++ < 50)
        {
            changed = false;
            for (var i = 0; i < steps.Count; i++)
            {
                var needs = JobSchedule.Role(steps[i].Job)?.Needs ?? [];
                var last = -1; var later = new List<string>();
                foreach (var n in needs)
                    for (var j = i + 1; j < steps.Count; j++)
                        if (steps[j].Job == n && St(steps[j]) != St(steps[i])) { if (j > last) last = j; if (!later.Contains(n)) later.Add(n); }
                if (last < 0) continue;
                var m = steps[i]; steps.RemoveAt(i);
                var at = last;                                                   // the needed step slid one place up: right after it ...
                while (at < steps.Count && moved.Contains(steps[at].Job)) at++;  // ... and after the steps moved there before
                steps.Insert(at, m with { Stage = St(steps[last - 1]), WithPrevious = false });
                if (!moved.Contains(m.Job)) moved.Add(m.Job);
                why[m.Job] = later.ToArray();
                changed = true;
                break;
            }
        }
        if (moved.Count == 0) return d;
        var notes = d.MigrationNotes.ToList();
        notes.AddRange(moved.Select(k => $"{k} now runs after {string.Join(", ", why[k])}: it reads its output"));
        return d with { Steps = FixGroups(steps), Stages = d.StageList, Migrated = true, MigrationNotes = notes };
    }

    /// A stored pipeline (schema 1 or 2) without a step that is never a step (OwnSchedule: the updater) -- the same rule as
    /// Remove-SIJobFlowOwnScheduleStep: each dropped step is said in MigrationNotes and the definition is Migrated (the page
    /// shows it; the next save stores it without the step); a step that started together with it starts on its own when it
    /// is now the first of its stage.
    public static FlowDefinition WithoutOwnSchedule(FlowDefinition d)
    {
        var drop = d.Steps.Where(s => OwnSchedule(s.Job) || Retired(s.Job)).ToList();
        if (drop.Count == 0) return d;
        var notes = d.MigrationNotes.ToList();
        notes.AddRange(drop.Select(x => Retired(x.Job)
            ? $"{x.Job} was a step of the stored pipeline and is taken out: {RetiredWhy}"
            : $"{x.Job} was a step of the stored pipeline and is taken out: {OwnScheduleWhy} (03:00 UTC), never inside the pipeline -- it waits while the pipeline runs, so as a step it waited for itself"));
        return d with { Steps = FixGroups(d.Steps.Where(s => !OwnSchedule(s.Job) && !Retired(s.Job)).ToList()), Stages = d.StageList, Migrated = true, MigrationNotes = notes };
    }

    /// <summary>
    /// A schema-1 flow (one list of steps) as a pipeline -- LOSSLESS, the same rules as ConvertFrom-SIPipelineSchema1:
    /// a job the map knows goes to its stage, an unknown (custom) step stays in the stage of the step above it; the stages
    /// run collect -> correlate -> deliver; "start together with the step above" is kept while that step is still above it
    /// in the same stage; a Deliver step with the old default (skip-dependents) gets the Deliver default (continue); the
    /// risk trend is kept but switched off (Risk Analysis writes the trend row now). The schedule keeps its time (UTC).
    /// </summary>
    public static FlowDefinition Migrate(FlowDefinition v1)
    {
        var notes = new List<string>();
        var by = StageIds.ToDictionary(s => s, _ => new List<FlowStep>());
        var prevStage = StageIds[0]; var prevJob = "";
        foreach (var s in v1.Steps)
        {
            var st = StageOf(s.Job);
            if (st == "" || !by.ContainsKey(st)) { st = prevStage; notes.Add($"{s.Job} is not a job SecurityInsight ships: it stays in the stage of the step above it ({StageName(st)})"); }
            var with = s.WithPrevious;
            if (with && (by[st].Count == 0 || by[st][^1].Job != prevJob)) { with = false; notes.Add($"{s.Job} started together with {(prevJob == "" ? "the step above" : prevJob)}; they are in different stages now, so it starts on its own"); }
            var of = s.OnFailure;
            if (st == "deliver" && of == "skip-dependents") { of = "continue"; notes.Add($"{s.Job} (Deliver): on failure is now 'continue' -- the Deliver targets are independent of each other"); }
            var en = s.Enabled;
            if (s.Job == "asset-trend" && en) { en = false; notes.Add("asset-trend is kept but switched off: Risk Analysis writes the daily trend row itself now"); }
            by[st].Add(s with { WithPrevious = with, OnFailure = of, Enabled = en, Stage = st });
            prevStage = st; prevJob = s.Job;
        }
        return v1 with { Steps = StageIds.SelectMany(x => by[x]).ToList(), Stages = StageIds.Select(NewStage).ToList(), Name = DefaultName, Migrated = true, MigrationNotes = notes };
    }

    // ---- groups, dependents, validation ----
    /// The steps as groups: a step with WithPrevious joins the group above it -- never across a stage. Group numbers from 1.
    public static IReadOnlyList<(int Group, int Order, FlowStep Step)> Ordered(FlowDefinition d)
    {
        var list = new List<(int, int, FlowStep)>();
        var g = 0; var prev = "";
        for (var i = 0; i < d.Steps.Count; i++)
        {
            var st = string.IsNullOrEmpty(d.Steps[i].Stage) ? "collect" : d.Steps[i].Stage;
            if (i == 0 || !d.Steps[i].WithPrevious || st != prev) g++;
            list.Add((g, i + 1, d.Steps[i]));
            prev = st;
        }
        return list;
    }

    public static (string[] Problems, string[] Warnings) Validate(FlowDefinition d)
    {
        var p = new List<string>(); var w = new List<string>();
        if (!System.Text.RegularExpressions.Regex.IsMatch(d.StartTime ?? "", @"^([01]\d|2[0-3]):[0-5]\d$")) p.Add($"the start time '{d.StartTime}' is not HH:mm");
        if (!Cadences.Contains(d.Cadence)) p.Add($"the cadence '{d.Cadence}' is not one of {string.Join(", ", Cadences)}");
        if (d.Cadence == "weekly" && d.Weekday is < 0 or > 6) p.Add("the weekday must be 0 (Sunday) to 6");
        if (d.Cadence == "interval" && d.IntervalMinutes is < 5 or > 10080) p.Add("the interval must be 5 minutes to 7 days (the rest between the end of one run and the start of the next)");
        if (!TryZone(d.TimeZone, out _)) w.Add($"the time zone '{d.TimeZone}' is not known -- the start time is read as UTC");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var pos = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (grp, order, s) in Ordered(d))
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(s.Job, @"^[a-z0-9][a-z0-9\-]{0,24}$")) { p.Add($"step {order}: '{s.Job}' is not a job"); continue; }
            if (!seen.Add(s.Job)) p.Add($"step {order}: {s.Job} is in the pipeline twice");
            if (OwnSchedule(s.Job)) p.Add($"step {order}: {s.Job} is never part of the pipeline -- {OwnScheduleWhy}");
            else if (Retired(s.Job)) p.Add($"step {order}: {s.Job} is never part of the pipeline -- {RetiredWhy}");
            else if (NeverInFlow(s.Job)) p.Add($"step {order}: {s.Job} is never part of the pipeline (it is started on demand)");
            if (!OnFailureChoices.Contains(s.OnFailure)) p.Add($"step {order} ({s.Job}): on failure '{s.OnFailure}' is not one of {string.Join(", ", OnFailureChoices)}");
            if (s.TimeoutMinutes is < 5 or > MaxStepTimeoutMinutes) p.Add($"step {order} ({s.Job}): the timeout must be 5-{MaxStepTimeoutMinutes} minutes");
            pos[s.Job] = grp;
        }
        foreach (var (grp, _, s) in Ordered(d))
            foreach (var n in JobSchedule.Role(s.Job)?.Needs ?? [])
                if (pos.TryGetValue(n, out var at) && at >= grp)
                    w.Add($"{JobSchedule.Label(s.Job)} runs {(at == grp ? "together with" : "before")} {JobSchedule.Label(n)}, which it needs -- it reads that job's output from the run before");
        // #306: the stages
        var ids = d.StageList.Select(s => s.Id).ToList();
        for (var i = 0; i < ids.Count; i++)
        {
            if (!IsStageId(ids[i])) p.Add($"stage {i + 1}: '{ids[i]}' is not a stage (collect, correlate, deliver or custom-<name>)");
            else if (ids.IndexOf(ids[i]) != i) p.Add($"stage {i + 1}: {ids[i]} is already stage {ids.IndexOf(ids[i]) + 1}");
        }
        if (ids.Contains("collect") && ids.Contains("deliver") && ids.IndexOf("deliver") < ids.IndexOf("collect")) p.Add("Deliver runs before Collect -- it would publish before the data is collected");
        var last = -1; var prevStage = "";
        foreach (var (_, order, s) in Ordered(d))
        {
            var st = string.IsNullOrEmpty(s.Stage) ? "collect" : s.Stage;
            var at = ids.IndexOf(st);
            if (at < 0) { p.Add($"step {order} ({s.Job}): its stage '{st}' is not a stage of the pipeline"); continue; }
            if (at < last) p.Add($"step {order} ({s.Job}): the steps must be in stage order -- {StageName(st)} comes before {StageName(prevStage)}");
            if (st != prevStage && s.WithPrevious && order > 1) w.Add($"step {order} ({s.Job}) is the first of {StageName(st)}: it cannot start together with a step of another stage -- it starts on its own");
            last = at; prevStage = st;
        }
        return (p.ToArray(), w.ToArray());
    }

    /// The steps that need -job, directly or through another step -- skipped when it fails (on failure: skip-dependents).
    public static string[] Dependents(FlowDefinition d, string job)
    {
        var inFlow = d.Steps.Select(s => s.Job).ToList();
        var outList = new List<string>(); var q = new Queue<string>(); q.Enqueue(job);
        while (q.Count > 0)
        {
            var x = q.Dequeue();
            foreach (var k in inFlow)
                if (k != job && !outList.Contains(k) && (JobSchedule.Role(k)?.Needs.Contains(x) ?? false)) { outList.Add(k); q.Enqueue(k); }
        }
        return outList.ToArray();
    }

    // ---- the edits Operations > Jobs makes ----
    private static string StageOfStep(FlowStep s) => string.IsNullOrEmpty(s.Stage) ? "collect" : s.Stage;

    /// One place up / down. Within its stage it swaps with its neighbour; at the edge of its stage it moves into the stage
    /// above / below (last / first there). The first step of a stage never starts together with the step above.
    public static FlowDefinition Move(FlowDefinition d, string job, int delta)
    {
        var steps = d.Steps.ToList();
        var i = steps.FindIndex(s => s.Job == job);
        if (i < 0) throw new ArgumentException($"{job} is not a step of the pipeline");
        var ids = d.StageList.Select(s => s.Id).ToList();
        var st = StageOfStep(steps[i]);
        var j = i + delta;
        var neighbourSameStage = j >= 0 && j < steps.Count && StageOfStep(steps[j]) == st;
        if (neighbourSameStage) (steps[i], steps[j]) = (steps[j], steps[i]);
        else
        {
            var at = ids.IndexOf(st) + Math.Sign(delta);
            if (at < 0 || at >= ids.Count) return d;
            steps[i] = steps[i] with { Stage = ids[at], WithPrevious = false };
            steps = SortByStage(steps, ids);
        }
        return d with { Steps = FixGroups(steps), Stages = d.StageList };
    }

    /// A step into another stage (as its last step).
    public static FlowDefinition MoveToStage(FlowDefinition d, string job, string stage)
    {
        var ids = d.StageList.Select(s => s.Id).ToList();
        if (!ids.Contains(stage)) throw new ArgumentException($"'{stage}' is not a stage of the pipeline");
        var steps = d.Steps.ToList();
        var i = steps.FindIndex(s => s.Job == job);
        if (i < 0) throw new ArgumentException($"{job} is not a step of the pipeline");
        var s = steps[i] with { Stage = stage, WithPrevious = false };
        steps.RemoveAt(i);
        var lastOf = steps.FindLastIndex(x => StageOfStep(x) == stage);
        var insertAt = lastOf >= 0 ? lastOf + 1 : steps.FindIndex(x => ids.IndexOf(StageOfStep(x)) > ids.IndexOf(stage)) is var k && k >= 0 ? k : steps.Count;
        steps.Insert(insertAt, s);
        return d with { Steps = FixGroups(steps), Stages = d.StageList };
    }

    private static List<FlowStep> SortByStage(List<FlowStep> steps, List<string> ids) =>
        steps.Select((s, n) => (s, n)).OrderBy(x => ids.IndexOf(StageOfStep(x.s)) < 0 ? int.MaxValue : ids.IndexOf(StageOfStep(x.s))).ThenBy(x => x.n).Select(x => x.s).ToList();

    private static List<FlowStep> FixGroups(List<FlowStep> steps)
    {
        for (var k = 0; k < steps.Count; k++)
            if (steps[k].WithPrevious && (k == 0 || StageOfStep(steps[k - 1]) != StageOfStep(steps[k]))) steps[k] = steps[k] with { WithPrevious = false };
        return steps;
    }

    /// A job joins the pipeline in its stage (the map's), at its place in the default order (after the last step that comes
    /// before it there), else last in that stage.
    public static FlowDefinition Include(FlowDefinition d, string job)
    {
        var key = JobSchedule.Key(job);
        if (OwnSchedule(key)) throw new ArgumentException($"{JobSchedule.Label(key)} is never part of the pipeline -- {OwnScheduleWhy} (03:00 UTC)");
        if (Retired(key)) throw new ArgumentException($"{JobSchedule.Label(key)} is never part of the pipeline -- {RetiredWhy}");
        if (NeverInFlow(key)) throw new ArgumentException($"{JobSchedule.Label(key)} is never part of the pipeline (it is started on demand)");
        if (d.Steps.Any(s => s.Job == key)) return d;
        var ids = d.StageList.Select(s => s.Id).ToList();
        var stage = StageOf(key) is { Length: > 0 } st && ids.Contains(st) ? st : ids.LastOrDefault() ?? "collect";
        var steps = d.Steps.ToList();
        var rank = Array.IndexOf(DefaultOrder, key);
        var inStage = steps.Select((s, n) => (s, n)).Where(x => StageOfStep(x.s) == stage).ToList();
        int at;
        if (rank >= 0 && inStage.Count > 0)
        {
            var before = inStage.LastOrDefault(x => Array.IndexOf(DefaultOrder, x.s.Job) is var r && r >= 0 && r < rank);
            at = before.s is null ? inStage[0].n : before.n + 1;
        }
        else if (inStage.Count > 0) at = inStage[^1].n + 1;
        else { var next = steps.FindIndex(x => ids.IndexOf(StageOfStep(x)) > ids.IndexOf(stage)); at = next >= 0 ? next : steps.Count; }
        steps.Insert(at, new FlowStep(key, OnFailure: StageOnFailure(stage), TimeoutMinutes: DefaultTimeout.TryGetValue(key, out var t) ? t : 240, Stage: stage));
        return d with { Steps = FixGroups(steps), Stages = d.StageList };
    }

    public static FlowDefinition Remove(FlowDefinition d, string job)
    {
        if (Required(job)) throw new ArgumentException($"{JobSchedule.Label(JobSchedule.Key(job))} is not removed from the pipeline -- {RequiredWhy}");
        var steps = d.Steps.Where(s => s.Job != JobSchedule.Key(job)).ToList();
        return d with { Steps = FixGroups(steps), Stages = d.StageList };
    }

    // A step's timeout: 5 minutes to 72 hours (the same range the pipeline runner accepts, SI-JobFlow.ps1). The runner never
    // stops a step before its job's own run limit, so this value only matters when it is the longer of the two.
    public const int MaxStepTimeoutMinutes = 4320;

    public static FlowDefinition Update(FlowDefinition d, string job, bool enabled, bool withPrevious, string onFailure, int timeoutMinutes)
    {
        var steps = d.Steps.ToList();
        var i = steps.FindIndex(s => s.Job == job);
        if (i < 0) throw new ArgumentException($"{job} is not a step of the pipeline");
        if (!OnFailureChoices.Contains(onFailure)) throw new ArgumentException("on failure: skip the steps that need it, stop the pipeline, or continue");
        if (timeoutMinutes is < 5 or > MaxStepTimeoutMinutes) throw new ArgumentException($"the timeout must be 5-{MaxStepTimeoutMinutes} minutes");
        steps[i] = steps[i] with { Enabled = enabled, WithPrevious = i > 0 && withPrevious, OnFailure = onFailure, TimeoutMinutes = timeoutMinutes };
        return d with { Steps = FixGroups(steps), Stages = d.StageList };
    }

    /// A stage that starts even when the stage before it did not succeed (Deliver: never after a failed Collect).
    public static FlowDefinition WithStage(FlowDefinition d, string stage, bool runIfPreviousFailed)
    {
        var list = d.StageList.ToList();
        var i = list.FindIndex(s => s.Id == stage);
        if (i < 0) throw new ArgumentException($"'{stage}' is not a stage of the pipeline");
        list[i] = list[i] with { RunIfPreviousFailed = runIfPreviousFailed };
        return d with { Stages = list };
    }

    public static FlowDefinition WithCadence(FlowDefinition d, string cadence, string? startTime, int weekday, int intervalMinutes, string? timeZone = null)
    {
        var c = (cadence ?? "").Trim().ToLowerInvariant();
        var tz = string.IsNullOrWhiteSpace(timeZone) ? d.TimeZone : timeZone.Trim();
        if (!TryZone(tz, out _)) throw new ArgumentException($"the time zone '{tz}' is not known -- use an id such as Europe/Copenhagen or UTC");
        var n = d with { Cadence = c, StartTime = string.IsNullOrWhiteSpace(startTime) ? d.StartTime : startTime.Trim(), Weekday = weekday, IntervalMinutes = intervalMinutes, TimeZone = tz };
        var (p, _) = Validate(n with { Steps = Array.Empty<FlowStep>(), Stages = Array.Empty<FlowStage>() });
        if (p.Length > 0) throw new ArgumentException(p[0]);
        return n;
    }

    // ---- the time zone of the start time (#306: 22:00 local all year, daylight saving included) ----
    /// The zone by IANA or Windows id (both on Windows and Linux); false for an unknown id (the start time is then UTC).
    public static bool TryZone(string? id, out TimeZoneInfo zone)
    {
        zone = TimeZoneInfo.Utc;
        var want = (id ?? "").Trim();
        if (want is "" or "UTC" or "Etc/UTC" or "Z") return true;
        if (TimeZoneInfo.TryFindSystemTimeZoneById(want, out var z)) { zone = z; return true; }
        if (TimeZoneInfo.TryConvertIanaIdToWindowsId(want, out var win) && TimeZoneInfo.TryFindSystemTimeZoneById(win, out z)) { zone = z; return true; }
        if (TimeZoneInfo.TryConvertWindowsIdToIanaId(want, out var iana) && TimeZoneInfo.TryFindSystemTimeZoneById(iana, out z)) { zone = z; return true; }
        return false;
    }

    /// A local wall-clock time in -zone as UTC: a time that does not exist (spring forward) runs one hour later; a time that
    /// exists twice (fall back) is its first occurrence.
    public static DateTimeOffset ToUtc(DateTime local, TimeZoneInfo zone)
    {
        var l = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
        if (zone.IsInvalidTime(l)) l = l.AddHours(1);
        if (zone.IsAmbiguousTime(l)) return new DateTimeOffset(l - zone.GetAmbiguousTimeOffsets(l).Max(), TimeSpan.Zero);
        return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(l, zone), TimeSpan.Zero);
    }

    private static bool DayOk(FlowDefinition d, DateTime localDay) => d.Cadence switch
    {
        "weekdays" => localDay.DayOfWeek is not (DayOfWeek.Saturday or DayOfWeek.Sunday),
        "weekly" => (int)localDay.DayOfWeek == d.Weekday % 7,
        _ => true,
    };

    private static DateTime LocalSlot(FlowDefinition d, DateTime localDay)
    {
        var parts = (d.StartTime ?? DefaultStartTime).Split(':');
        return localDay.Date.AddHours(int.Parse(parts[0], CultureInfo.InvariantCulture)).AddMinutes(int.Parse(parts[1], CultureInfo.InvariantCulture));
    }

    /// "22:00 Europe/Copenhagen (20:00 UTC today)" -- or "01:00 UTC" for a UTC schedule.
    public static string StartText(FlowDefinition d, DateTimeOffset nowUtc)
    {
        if (d.TimeZone is "UTC" or "" || !TryZone(d.TimeZone, out var z) || z == TimeZoneInfo.Utc) return $"{d.StartTime} UTC";
        var u = ToUtc(LocalSlot(d, TimeZoneInfo.ConvertTime(nowUtc, z).DateTime), z);
        return $"{d.StartTime} {d.TimeZone} ({u.UtcDateTime.ToString("HH:mm", CultureInfo.InvariantCulture)} UTC today)";
    }

    // ---- SCHED-1.4: the cadence in words, and when the pipeline runs next ----
    public static string CadenceText(FlowDefinition d) => CadenceText(d, DateTimeOffset.UtcNow);
    public static string CadenceText(FlowDefinition d, DateTimeOffset nowUtc) => d.Cadence switch
    {
        "interval" => "Every " + Span(d.IntervalMinutes) + " after it finishes",
        "weekdays" => $"Weekdays at {StartText(d, nowUtc)}" + JobSchedule.NeverOverlaps,
        "weekly" => $"{(DayOfWeek)(d.Weekday % 7)}s at {StartText(d, nowUtc)}" + JobSchedule.NeverOverlaps,
        _ => $"Daily at {StartText(d, nowUtc)}" + JobSchedule.NeverOverlaps,
    };

    public static string Span(int minutes) => minutes % 60 == 0
        ? (minutes / 60 == 1 ? "1 hour" : $"{minutes / 60} hours")
        : (minutes < 60 ? $"{minutes} min" : $"{minutes / 60} h {minutes % 60} min");

    /// The latest time-of-day slot at or before now, as UTC (the start time read in the pipeline's time zone, each day).
    public static DateTimeOffset? LatestSlot(FlowDefinition d, DateTimeOffset nowUtc)
    {
        if (d.Cadence == "interval") return null;
        TryZone(d.TimeZone, out var z);
        var day = TimeZoneInfo.ConvertTime(nowUtc, z).DateTime.Date;
        for (var i = 0; i < 9; i++)
        {
            var local = LocalSlot(d, day.AddDays(-i));
            var t = ToUtc(local, z);
            if (t > nowUtc || !DayOk(d, local)) continue;
            return t;
        }
        return null;
    }

    public static DateTimeOffset? NextSlot(FlowDefinition d, DateTimeOffset nowUtc)
    {
        if (d.Cadence == "interval") return null;
        TryZone(d.TimeZone, out var z);
        var day = TimeZoneInfo.ConvertTime(nowUtc, z).DateTime.Date;
        for (var i = -1; i < 9; i++)
        {
            var local = LocalSlot(d, day.AddDays(i));
            var t = ToUtc(local, z);
            if (t <= nowUtc || !DayOk(d, local)) continue;
            return t;
        }
        return null;
    }

    /// When the pipeline runs next, in words (SCHED-1.1): interval = the last FINISH + the interval ("... (finished 10:08 + 5 min)"),
    /// or "after the current run finishes + 5 min" while one runs; time of day = the next slot, or "as soon as the current run
    /// finishes" when the slot passed while it ran. Returns (text, when) -- when is null when it depends on a run still going.
    public static (string Text, DateTimeOffset? When) NextRun(FlowDefinition d, FlowRun? last, DateTimeOffset nowUtc)
    {
        static string T(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
        static string H(DateTimeOffset t) => t.UtcDateTime.ToString("HH:mm", CultureInfo.InvariantCulture);
        var running = last is { Finished: false };
        if (d.Cadence == "interval")
        {
            if (running) return ($"after the current run finishes + {Span(d.IntervalMinutes)}", null);
            if (last?.EndedUtc is { } fin)
            {
                var next = fin.AddMinutes(d.IntervalMinutes);
                if (next < nowUtc) next = nowUtc;
                return ($"{T(next)} (finished {H(fin)} + {Span(d.IntervalMinutes)})", next);
            }
            return ("first run within 5 minutes (when the runner wakes)", nowUtc.AddMinutes(5));
        }
        var slot = NextSlot(d, nowUtc);
        if (running)
        {
            var passed = LatestSlot(d, nowUtc);
            if (passed is { } ps && last!.StartedUtc < ps) return ($"as soon as the current run finishes (the {H(ps)} UTC start waits in the queue, then runs once)", null);
        }
        return slot is { } s ? ($"{T(s)}{(running ? " -- if the current run has finished by then" : "")}", s) : ("not scheduled", null);
    }

    /// "Daily pipeline · Stage 2 of 3: Correlate (data structure)" while it runs, "Daily pipeline · succeeded" when it ended,
    /// "... (run now)" for a stage / step run. The stage is named as in the overview's headings (StageTitle).
    public static string StatusText(FlowDefinition d, FlowRun run)
    {
        var ids = d.StageList.Select(s => s.Id).ToList();
        string where = "";
        if (run.Scope == "step") where = $"step {run.Target}";
        else
        {
            var cur = run.Finished ? (run.Scope == "stage" ? run.Target : null)
                : ids.FirstOrDefault(id => run.Steps.Where(s => (s.Stage ?? d.Steps.FirstOrDefault(x => x.Job == s.Job)?.Stage ?? "collect") == id && s.ErrorClass != "before-rerun")
                                                    .Any(s => s.State is "Waiting" or "Running" or "Starting"));
            if (cur is { Length: > 0 } c && ids.Contains(c)) where = $"Stage {ids.IndexOf(c) + 1} of {ids.Count}: {StageTitle(d.StageList[ids.IndexOf(c)])}";
        }
        var parts = new List<string> { d.Name };
        if (where != "") parts.Add(where);
        if (run.Finished) parts.Add(ThrottledOnly(run) ? "throttled" : run.State.ToLowerInvariant());
        return string.Join(" · ", parts) + (run.Scope is "stage" or "step" ? " (run now)" : "");
    }

    /// #532 THROTTLE-IS-NORMAL (framework §12.18): the words for a step / run that Microsoft only throttled. Amber, never failed.
    public const string ThrottledText = "Microsoft throttled this run; it runs again automatically at its next scheduled time.";

    /// A step whose engine failed only because Microsoft throttled it (the runner records ErrorClass 'throttled').
    public static bool IsThrottled(FlowStepRun? r) => r is not null && r.State == "Failed" && r.ErrorClass == "throttled";

    /// A finished run whose only failures were throttled steps (Failed / TimedOut / Interrupted, every one throttled).
    public static bool ThrottledOnly(FlowRun run)
    {
        if (run.State is not ("Failed" or "Stopped")) return false;
        var bad = run.Steps.Where(s => s.State is "Failed" or "TimedOut" or "Interrupted").ToList();
        return bad.Count > 0 && bad.All(IsThrottled);
    }

    /// A stage's status chip on the Jobs page, from its steps' newest records: running | failed | skipped | succeeded |
    /// waiting | not run yet; and when it started and ended (the first start, the last end).
    public sealed record StageStatus(string State, DateTimeOffset? Started, DateTimeOffset? Ended)
    {
        public TimeSpan? Duration => Started is { } a && Ended is { } b && b >= a ? b - a : null;
    }

    public static StageStatus StageSummary(IEnumerable<FlowStepRun?> steps)
    {
        var s = steps.Where(x => x is not null).Select(x => x!).ToList();
        if (s.Count == 0) return new("not run yet", null, null);
        var started = s.Where(x => x.StartedUtc is not null).Select(x => x.StartedUtc!.Value).DefaultIfEmpty().Min();
        var ended = s.Where(x => x.EndedUtc is not null).Select(x => x.EndedUtc!.Value).DefaultIfEmpty().Max();
        DateTimeOffset? a = started == default ? null : started, b = ended == default ? null : ended;
        var state = s.Any(x => x.State is "Running" or "Starting") ? "running"
            : s.Any(x => x.State is "Failed" or "TimedOut" or "Interrupted" && !IsThrottled(x)) ? "failed"
            : s.Any(IsThrottled) ? "throttled"
            : s.Any(x => x.State == "Skipped") ? "skipped"
            : s.All(x => x.State is "Success" or "Disabled") ? "succeeded"
            : "waiting";
        return new(state, a, state == "running" ? null : b);
    }

    /// "45 s" / "8 min" / "1 h 05 min".
    public static string DurationText(TimeSpan d) => d.TotalSeconds < 60 ? $"{(int)d.TotalSeconds} s"
        : d.TotalMinutes < 60 ? $"{(int)Math.Round(d.TotalMinutes)} min"
        : $"{(int)d.TotalHours} h {d.Minutes:00} min";

    /// "Every day at 22:00 (Europe/Copenhagen)" -- the schedule in plain words for the pipeline's header.
    public static string ScheduleWords(FlowDefinition d) => d.Cadence switch
    {
        "interval" => "Every " + Span(d.IntervalMinutes) + " after the previous run finishes",
        "weekdays" => $"Every weekday at {d.StartTime} ({d.TimeZone})",
        "weekly" => $"Every {(DayOfWeek)(d.Weekday % 7)} at {d.StartTime} ({d.TimeZone})",
        _ => $"Every day at {d.StartTime} ({d.TimeZone})",
    };

    /// What a queue request runs, in words: "the pipeline", "stage Correlate", "step Data sync", "the pipeline from ...".
    public static string RequestText(string scope, string target) => scope switch
    {
        "stage" => "stage " + StageName(target),
        "step" => "step " + JobSchedule.Label(target),
        "from-step" => "the pipeline from " + JobSchedule.Label(target),
        _ => "the pipeline",
    };

    // ---- switching between the pipeline and per-job timers (the preview; the page carries it out) ----
    /// What switching to -mode does to each job. flow: a job of the pipeline on a timer loses it (Disable: remembered in the tag),
    /// caj-si-flow gets its wake-up timer; the risk trend's job waits too (Risk Analysis writes the trend row). schedules: a job
    /// of the pipeline gets its remembered timer back, or the default one in dependency order; caj-si-flow waits (Disable).
    /// The updater keeps its own timer in both modes (one an earlier switch took is given back). Jobs outside the pipeline,
    /// event jobs and the template job are kept.
    public static IReadOnlyList<FlowSwitchRow> SwitchPlan(IEnumerable<JobInfo> jobs, string mode, FlowDefinition definition)
    {
        var inFlow = WithoutOwnSchedule(definition).Steps.Select(s => s.Job).ToList();
        var rows = new List<FlowSwitchRow>();
        foreach (var j in jobs.OrderBy(x => x.Name, StringComparer.Ordinal))
        {
            var k = JobSchedule.Key(j.Name);
            if (j.TriggerType.Equals("Event", StringComparison.OrdinalIgnoreCase)) { rows.Add(new(j.Name, "keep", null, "event-triggered (scaled by its queue)")); continue; }
            if (k == "flow")
            {
                if (mode == "flow") rows.Add(j.Enabled ? new(j.Name, "keep", j.Cron, "the runner's wake-up is on") : new(j.Name, "to-schedule", TickCron, "wakes the runner every 5 minutes; the pipeline starts " + CadenceText(definition).ToLowerInvariant()));
                else rows.Add(j.Enabled ? new(j.Name, "to-manual", j.Cron, "the pipeline waits (its wake-up is remembered)") : new(j.Name, "keep", null, "the pipeline is already off"));
                continue;
            }
            // UPDATE-1.6: the updater keeps its OWN timer in every mode -- and gets back one an earlier switch took away
            if (OwnSchedule(k))
            {
                if (j.Enabled) rows.Add(new(j.Name, "keep", j.Cron, OwnScheduleWhy + " -- never a step of the pipeline"));
                else if (j.DisabledCron is { Length: > 0 } urc) rows.Add(new(j.Name, "to-schedule", urc, OwnScheduleWhy + " -- its timer, taken away by an earlier switch, comes back"));
                else rows.Add(new(j.Name, "keep", null, $"the updater has no timer and none is remembered -- give it its daily schedule (18:30 in the local time of the install's Azure region) with setup\\Install-SIUpdaterJob.ps1"));
                continue;
            }
            // #412: a retired job (asset-properties) does nothing any more -- its timer is turned off in both modes
            if (Retired(k))
            {
                rows.Add(j.Enabled ? new(j.Name, "to-manual", j.Cron, RetiredWhy + " (its timer is remembered)") : new(j.Name, "keep", null, RetiredWhy));
                continue;
            }
            var step = inFlow.IndexOf(k);
            if (step < 0 && ManualInFlowMode(k))
            {
                if (mode == "flow") rows.Add(j.Enabled ? new(j.Name, "to-manual", j.Cron, "Risk Analysis writes the daily trend row itself -- the job is kept for a run by hand (its timer is remembered)") : new(j.Name, "keep", null, "runs by hand only"));
                else if (j.Enabled) rows.Add(new(j.Name, "keep", j.Cron, "already on its own timer"));
                else rows.Add(new(j.Name, "to-schedule", j.DisabledCron is { Length: > 0 } trc ? trc : DefaultCron[k], "its own timer again"));
                continue;
            }
            if (step < 0) { rows.Add(new(j.Name, "keep", j.Cron, "not in the pipeline -- keeps its own schedule")); continue; }
            if (mode == "flow")
                rows.Add(j.Enabled ? new(j.Name, "to-manual", j.Cron, $"step {step + 1} of the pipeline -- its timer {j.Cron} is remembered") : new(j.Name, "keep", null, $"step {step + 1} of the pipeline"));
            else if (j.Enabled) rows.Add(new(j.Name, "keep", j.Cron, "already on its own timer"));
            else if (j.DisabledCron is { Length: > 0 } rc) rows.Add(new(j.Name, "to-schedule", rc, "its remembered timer"));
            else rows.Add(new(j.Name, "to-schedule", DefaultCron.TryGetValue(k, out var dc) ? dc : "0 4 * * *", "the default timer (dependency order)"));
        }
        return rows;
    }

    /// The mode the install runs in when nothing is stored: the pipeline when caj-si-flow's timer is on, else schedules.
    public static string InferMode(IEnumerable<JobInfo> jobs) => jobs.Any(j => j.Name == FlowJob && j.Enabled) ? "flow" : "schedules";
}
