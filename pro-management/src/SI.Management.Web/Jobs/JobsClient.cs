using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Azure.Core;
using Microsoft.Extensions.Options;
using SI.Management.Core;

namespace SI.Management.Web.Jobs;

/// Where the installation's Container Apps jobs live (section "Jobs"). Read through ARM with the web app's managed
/// identity: Reader on the resource group lists them; "Container Apps Jobs Contributor" changes and starts them.
public sealed class JobsOptions
{
    public const string Section = "Jobs";
    public string SubscriptionId { get; set; } = "";
    public string ResourceGroup { get; set; } = "";
    /// Only jobs whose name starts with this are shown and can be acted on (empty = every job in the group).
    public string NamePrefix { get; set; } = "";
    public string ApiVersion { get; set; } = "2024-03-01";
    /// The manual-trigger job that publishes an accepted template release (Bootstrap creates it as caj-si-templates).
    public string TemplatesJob { get; set; } = "caj-si-templates";
    /// The product updater job (CR5 step 1: the install's own name, Jobs__UpdaterJob; today's name by default). The web app
    /// starts its short "apply settings" run, and it is SuperAdmin-only.
    public string UpdaterJob { get; set; } = "caj-si-updater";
    /// PURE. The updater job's name: the configured one, else today's name.
    public string UpdaterJobName => string.IsNullOrWhiteSpace(UpdaterJob) ? "caj-si-updater" : UpdaterJob.Trim();
    /// The close-loop mail job, which also sends the exemption mails (#252). The web app starts one execution of it
    /// (SI_EXEMPTION_MAIL_ONLY=1) after queueing a request or decision mail; empty = wait for its daily run.
    public string CloseLoopMailJob { get; set; } = "caj-si-close-loop-mail";
    public bool IsConfigured => !string.IsNullOrWhiteSpace(SubscriptionId) && !string.IsNullOrWhiteSpace(ResourceGroup);
    /// CR8 (framework 12.11f item 1): "direct" (default -- the web app changes a job's trigger itself, which needs Container
    /// Apps Jobs Contributor) or "request" (the web app holds start-only rights; a trigger change is a cfg.JobTriggerRequest
    /// row the pipeline runner applies -- RequestedTriggerJobsClient). Set by setup / the security cut-over with the roles.
    public string ChangeMode { get; set; } = "direct";
    public bool ChangesAreRequests => string.Equals((ChangeMode ?? "").Trim(), "request", StringComparison.OrdinalIgnoreCase);
}

public sealed record JobInfo(string Name, string TriggerType, string? Cron, string? DisabledCron, string? Image, string? ProvisioningState)
{
    public bool Enabled => TriggerType.Equals("Schedule", StringComparison.OrdinalIgnoreCase);
    public bool Disabled => DisabledCron is not null && TriggerType.Equals("Manual", StringComparison.OrdinalIgnoreCase);
    /// The updater job's recorded nightly zone (tag si-nightly-schedule "18:30 &lt;zone&gt;") and region (tag si-nightly-region).
    public string? NightlySchedule { get; init; }
    public string? NightlyRegion { get; init; }
}

public sealed record JobExecution(string Name, string Status, DateTimeOffset? StartTime, DateTimeOffset? EndTime);

public interface IJobsClient
{
    bool IsConfigured { get; }
    Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct);
    Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct);
    Task<string> StartAsync(string job, CancellationToken ct);
    /// Start one execution with extra environment variables (the job's own stay; a name given here replaces its value
    /// for this execution only). Returns the execution name.
    Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct);
    Task SetCronAsync(string job, string cron, CancellationToken ct);
    Task DisableAsync(string job, CancellationToken ct);
    Task EnableAsync(string job, CancellationToken ct);
    /// #269: a Manual job back on a timer with -cron (leaving the flow, or switching to schedules when no timer was
    /// remembered). The remembered-timer tag is removed.
    Task ScheduleAsync(string job, string cron, CancellationToken ct);
    /// CR8: the trigger changes this client REQUESTED (not made) during this request -- empty for a client that makes them.
    IReadOnlyList<string> RequestedTriggerChanges => Array.Empty<string>();
}

public static partial class JobRules
{
    /// The tag that remembers a disabled job's schedule, so enabling restores exactly what was there.
    public const string DisabledCronTag = "si-disabled-cron";

    [GeneratedRegex(@"^[a-z0-9][a-z0-9\-]{0,31}$", RegexOptions.CultureInvariant)] public static partial Regex JobName();
    [GeneratedRegex(@"^[0-9*/,\-]{1,40}( [0-9*/,\-]{1,40}){4}$", RegexOptions.CultureInvariant)] public static partial Regex Cron();

    public static string Name(string job) =>
        JobName().IsMatch(job ?? "") ? job! : throw new ArgumentException($"'{job}' is not a Container Apps job name");

    /// PURE. Of a job's executions, the one that is running now (Running / Processing; the one that started first), or
    /// null. A job that is already running is not started a second time beside itself.
    public static JobExecution? RunningExecution(IEnumerable<JobExecution> executions) =>
        executions.Where(e => e.Status is "Running" or "Processing").OrderBy(e => e.StartTime ?? DateTimeOffset.MaxValue).FirstOrDefault();

    /// PURE. A queue worker job runs several executions at once by design: it is never held back by one that is running.
    public static bool RunsSideBySide(string job) => (job ?? "").EndsWith("-worker", StringComparison.OrdinalIgnoreCase);

    /// PURE. What "run now" answers when the job is already running: it says so and starts nothing.
    public static string AlreadyRunningText(JobExecution live)
    {
        var started = live.StartTime is { } t ? ", started " + t.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : "";
        return "not started -- it is already running (execution " + live.Name + started + "), and a second run is never started beside it";
    }

    public static string CronOf(string cron)
    {
        var c = Regex.Replace((cron ?? "").Trim(), @"\s+", " ");
        return Cron().IsMatch(c) ? c : throw new ArgumentException("the schedule must be a 5-field cron expression (minute hour day month weekday), e.g. '0 3 * * *'");
    }

    // Every trigger change below returns an ARM PATCH body with ONLY what changes -- { tags?, properties: { configuration:
    // { triggerType, replicaTimeout, manualTriggerConfig | scheduleTriggerConfig } } } -- never the whole job. ARM's GET
    // returns secrets WITHOUT their values, so a PUT of the GET'd job is refused for any job that has a secret
    // (ContainerAppSecretInvalid -- found live on the Pro jobs that carry si-license, #269). The GET'd job is not changed.
    // The PowerShell twin is ConvertTo-SIArmJobTrigger (engine/_shared/SI-JobFlow.ps1).

    /// The PATCH body that makes a GET'd job Manual (disabled), remembering the cron in a tag.
    public static JsonObject Disabled(JsonObject job)
    {
        var cfg = ConfigOf(job);
        if (!string.Equals((string?)cfg["triggerType"], "Schedule", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("only a scheduled job can be disabled");
        var sched = cfg["scheduleTriggerConfig"] as JsonObject ?? new JsonObject();
        var tags = TagsOf(job);
        tags[DisabledCronTag] = (string?)sched["cronExpression"];
        return Patch(cfg, tags, "Manual", new JsonObject { ["parallelism"] = sched["parallelism"]?.DeepClone() ?? 1, ["replicaCompletionCount"] = sched["replicaCompletionCount"]?.DeepClone() ?? 1 });
    }

    /// The reverse: back to Schedule with the remembered cron (the tag is removed).
    public static JsonObject Enabled(JsonObject job)
    {
        var cfg = ConfigOf(job);
        var tags = TagsOf(job);
        var cron = (string?)tags[DisabledCronTag] ?? throw new InvalidOperationException("this job was not disabled here: it has no remembered schedule -- set one with 'Change schedule'");
        tags.Remove(DisabledCronTag);
        return Patch(cfg, tags, "Schedule", ScheduleFrom(cfg["manualTriggerConfig"] as JsonObject, cron));
    }

    /// #269: Manual -> Schedule with the given cron (the remembered one is not needed and is removed).
    public static JsonObject Scheduled(JsonObject job, string cron)
    {
        var cfg = ConfigOf(job);
        if (string.Equals((string?)cfg["triggerType"], "Schedule", StringComparison.OrdinalIgnoreCase)) return WithCron(job, cron);
        if (string.Equals((string?)cfg["triggerType"], "Event", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("an event-triggered job is started by its queue -- it has no schedule");
        var tags = TagsOf(job);
        tags.Remove(DisabledCronTag);
        return Patch(cfg, tags, "Schedule", ScheduleFrom(cfg["manualTriggerConfig"] as JsonObject, cron));
    }

    /// A scheduled job's new cron (its tags are not touched, so they are not in the body).
    public static JsonObject WithCron(JsonObject job, string cron)
    {
        var cfg = ConfigOf(job);
        if (!string.Equals((string?)cfg["triggerType"], "Schedule", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("only a scheduled job has a schedule -- enable it first");
        return Patch(cfg, null, "Schedule", ScheduleFrom(cfg["scheduleTriggerConfig"] as JsonObject, cron));
    }

    private static JsonObject ConfigOf(JsonObject job) =>
        job["properties"]?["configuration"] as JsonObject ?? throw new InvalidOperationException("the job has no configuration");

    /// A copy of the job's tags (a PATCH replaces the tag set, so every existing tag is carried).
    private static JsonObject TagsOf(JsonObject job) => (job["tags"] as JsonObject)?.DeepClone() as JsonObject ?? new JsonObject();

    private static JsonObject ScheduleFrom(JsonObject? from, string cron) => new()
    {
        ["cronExpression"] = CronOf(cron),
        ["parallelism"] = from?["parallelism"]?.DeepClone() ?? 1,
        ["replicaCompletionCount"] = from?["replicaCompletionCount"]?.DeepClone() ?? 1,
    };

    private static JsonObject Patch(JsonObject cfg, JsonObject? tags, string trigger, JsonObject triggerConfig)
    {
        var c = new JsonObject { ["triggerType"] = trigger };
        if (cfg["replicaTimeout"] is { } rt) c["replicaTimeout"] = rt.DeepClone();
        c[trigger == "Manual" ? "manualTriggerConfig" : "scheduleTriggerConfig"] = triggerConfig;
        var body = new JsonObject();
        if (tags is not null) body["tags"] = tags;
        body["properties"] = new JsonObject { ["configuration"] = c };
        return body;
    }

    /// The readable reason from an ARM error response ("<code>: <message>"), or null when the body has none.
    public static string? ArmError(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try
        {
            var e = JsonNode.Parse(text)?["error"];
            var code = (string?)e?["code"]; var msg = (string?)e?["message"];
            if (msg is null) return null;
            var r = code is null || msg.Contains(code, StringComparison.Ordinal) ? msg : $"{code}: {msg}";
            return r.Length > 800 ? r[..800] + "..." : r;
        }
        catch (JsonException) { return null; }
    }

    [GeneratedRegex(@"^[A-Z][A-Z0-9_]{0,63}$", RegexOptions.CultureInvariant)] public static partial Regex EnvName();

    /// The body of POST .../jobs/{job}/start for one execution with extra environment variables: the job's first
    /// container (name, image, resources, command, args) with its env -- secret references included -- plus -env, a name
    /// given in -env replacing the job's value. Nothing else of the job changes; the next execution runs as configured.
    public static JsonObject StartTemplate(JsonObject job, IReadOnlyDictionary<string, string> env)
    {
        var c = (job["properties"]?["template"]?["containers"] as JsonArray)?.FirstOrDefault() as JsonObject
                ?? throw new InvalidOperationException("the job has no container to start");
        foreach (var k in env.Keys) if (!EnvName().IsMatch(k)) throw new ArgumentException($"'{k}' is not an environment variable name");
        var list = new JsonArray();
        foreach (var e in (c["env"] as JsonArray ?? new JsonArray()).OfType<JsonObject>())
            if (!env.ContainsKey((string?)e["name"] ?? "")) list.Add(e.DeepClone());
        foreach (var kv in env.OrderBy(k => k.Key, StringComparer.Ordinal)) list.Add(new JsonObject { ["name"] = kv.Key, ["value"] = kv.Value });
        var container = new JsonObject { ["name"] = c["name"]?.DeepClone(), ["image"] = c["image"]?.DeepClone(), ["env"] = list };
        foreach (var keep in new[] { "resources", "command", "args" }) if (c[keep] is not null) container[keep] = c[keep]!.DeepClone();
        return new JsonObject { ["containers"] = new JsonArray(container) };
    }

    public static JobInfo Map(JsonObject j)
    {
        var cfg = j["properties"]?["configuration"];
        var image = j["properties"]?["template"]?["containers"] is JsonArray a && a.Count > 0 ? (string?)a[0]?["image"] : null;
        return new JobInfo((string?)j["name"] ?? "", (string?)cfg?["triggerType"] ?? "", (string?)cfg?["scheduleTriggerConfig"]?["cronExpression"],
            (string?)j["tags"]?[DisabledCronTag], image, (string?)j["properties"]?["provisioningState"])
        {
            NightlySchedule = (string?)j["tags"]?[JobFlow.NightlyScheduleTag], NightlyRegion = (string?)j["tags"]?[JobFlow.NightlyRegionTag],
        };
    }
}

/// ARM over HTTPS with the process's ONE credential (managed identity hosted). No SDK: four REST calls.
public sealed class ArmJobsClient : IJobsClient
{
    private static readonly string[] Scopes = ["https://management.azure.com/.default"];
    private readonly HttpClient _http;
    private readonly TokenCredential _cred;
    private readonly JobsOptions _o;

    public ArmJobsClient(HttpClient http, TokenCredential cred, IOptions<JobsOptions> o) { _http = http; _cred = cred; _o = o.Value; }

    public bool IsConfigured => _o.IsConfigured;

    private string Base => $"https://management.azure.com/subscriptions/{Uri.EscapeDataString(_o.SubscriptionId)}/resourceGroups/{Uri.EscapeDataString(_o.ResourceGroup)}/providers/Microsoft.App/jobs";
    private string V => "api-version=" + Uri.EscapeDataString(_o.ApiVersion);

    private async Task<JsonNode?> SendAsync(HttpMethod m, string url, JsonNode? body, CancellationToken ct)
    {
        var token = await _cred.GetTokenAsync(new TokenRequestContext(Scopes), ct);
        using var req = new HttpRequestMessage(m, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        if (body is not null) req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
        {
            var hint = resp.StatusCode == System.Net.HttpStatusCode.Forbidden
                ? " -- the web app's identity needs Reader (to list) and Container Apps Jobs Contributor (to change or start) on the resource group"
                : "";
            var why = JobRules.ArmError(text) is { } e ? ": " + e : "";
            throw new InvalidOperationException($"ARM {m} returned {(int)resp.StatusCode}{why}{hint}");
        }
        return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
    }

    private async Task<JsonObject> GetJobAsync(string job, CancellationToken ct)
    {
        await EnsureListedAsync(job, ct);
        return (await SendAsync(HttpMethod.Get, $"{Base}/{JobRules.Name(job)}?{V}", null, ct)) as JsonObject ?? throw new InvalidOperationException($"job {job} not found");
    }

    /// An action is allowed only on a job the list shows (the prefix filter applies to writes too).
    private async Task EnsureListedAsync(string job, CancellationToken ct)
    {
        JobRules.Name(job);
        if (!(await ListAsync(ct)).Any(j => j.Name == job)) throw new ArgumentException($"'{job}' is not one of this installation's jobs");
    }

    public async Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct)
    {
        var list = new List<JobInfo>();
        string? url = $"{Base}?{V}";
        for (var page = 0; url is not null && page < 20; page++)
        {
            var node = await SendAsync(HttpMethod.Get, url, null, ct);
            foreach (var j in node?["value"]?.AsArray() ?? new JsonArray()) if (j is JsonObject o) list.Add(JobRules.Map(o));
            url = (string?)node?["nextLink"];
            if (url is not null && !url.StartsWith("https://management.azure.com/", StringComparison.OrdinalIgnoreCase)) url = null;
        }
        return list.Where(j => string.IsNullOrEmpty(_o.NamePrefix) || j.Name.StartsWith(_o.NamePrefix, StringComparison.OrdinalIgnoreCase))
                   .OrderBy(j => j.Name, StringComparer.Ordinal).ToList();
    }

    public async Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct)
    {
        await EnsureListedAsync(job, ct);
        var node = await SendAsync(HttpMethod.Get, $"{Base}/{JobRules.Name(job)}/executions?{V}", null, ct);
        return (node?["value"]?.AsArray() ?? new JsonArray()).OfType<JsonObject>().Select(e => new JobExecution(
                (string?)e["name"] ?? "", (string?)e["properties"]?["status"] ?? "",
                DateTimeOffset.TryParse((string?)e["properties"]?["startTime"], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var s) ? s : null,
                DateTimeOffset.TryParse((string?)e["properties"]?["endTime"], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var en) ? en : null))
            .OrderByDescending(e => e.StartTime).Take(Math.Clamp(top, 1, 100)).ToList();
    }

    public async Task<string> StartAsync(string job, CancellationToken ct)
    {
        await EnsureListedAsync(job, ct);
        var node = await SendAsync(HttpMethod.Post, $"{Base}/{JobRules.Name(job)}/start?{V}", new JsonObject(), ct);
        return (string?)node?["name"] ?? "(started)";
    }

    public async Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct)
    {
        var body = JobRules.StartTemplate(await GetJobAsync(job, ct), env);
        var node = await SendAsync(HttpMethod.Post, $"{Base}/{JobRules.Name(job)}/start?{V}", body, ct);
        return (string?)node?["name"] ?? "(started)";
    }

    // PATCH, never PUT: the bodies carry only the trigger (+ tags) -- see JobRules (#269).
    public async Task SetCronAsync(string job, string cron, CancellationToken ct) =>
        await SendAsync(HttpMethod.Patch, $"{Base}/{JobRules.Name(job)}?{V}", JobRules.WithCron(await GetJobAsync(job, ct), cron), ct);

    public async Task DisableAsync(string job, CancellationToken ct) =>
        await SendAsync(HttpMethod.Patch, $"{Base}/{JobRules.Name(job)}?{V}", JobRules.Disabled(await GetJobAsync(job, ct)), ct);

    public async Task EnableAsync(string job, CancellationToken ct) =>
        await SendAsync(HttpMethod.Patch, $"{Base}/{JobRules.Name(job)}?{V}", JobRules.Enabled(await GetJobAsync(job, ct)), ct);

    public async Task ScheduleAsync(string job, string cron, CancellationToken ct) =>
        await SendAsync(HttpMethod.Patch, $"{Base}/{JobRules.Name(job)}?{V}", JobRules.Scheduled(await GetJobAsync(job, ct), cron), ct);
}

public sealed class NotConfiguredJobsClient : IJobsClient
{
    public const string Why = "The jobs view is not configured for this installation (Jobs:SubscriptionId / Jobs:ResourceGroup).";
    public bool IsConfigured => false;
    public Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<JobInfo>>(Array.Empty<JobInfo>());
    public Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct) => Task.FromResult<IReadOnlyList<JobExecution>>(Array.Empty<JobExecution>());
    public Task<string> StartAsync(string job, CancellationToken ct) => throw new InvalidOperationException(Why);
    public Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct) => throw new InvalidOperationException(Why);
    public Task SetCronAsync(string job, string cron, CancellationToken ct) => throw new InvalidOperationException(Why);
    public Task DisableAsync(string job, CancellationToken ct) => throw new InvalidOperationException(Why);
    public Task EnableAsync(string job, CancellationToken ct) => throw new InvalidOperationException(Why);
    public Task ScheduleAsync(string job, string cron, CancellationToken ct) => throw new InvalidOperationException(Why);
}

public sealed partial record ConsoleLine(DateTimeOffset? At, string Execution, string Text)
{
    /// PowerShell colours its warnings with terminal escape codes (ESC[33;1m ... ESC[0m); a web page shows them as
    /// garbage, so they are removed (the ESC character itself may already be gone in the stored log line).
    public static string Clean(string? text) => string.IsNullOrEmpty(text) ? "" : AnsiCode().Replace(text, "");

    [GeneratedRegex(@"\u001b?\[[0-9;]{0,20}m")]
    private static partial Regex AnsiCode();
}

/// The console output of the installation's jobs (ContainerAppConsoleLogs in the SI workspace -- the environment's
/// diagnostic setting sends it there). Read through the shared, read-only Log Analytics reader.
public interface IConsoleLogReader
{
    Task<QueryResult<IReadOnlyList<ConsoleLine>>> ReadAsync(string job, string? execution, int hours, int top, string? contains, CancellationToken ct);

    /// The connector summary lines of every job: the close-loop's plan line and HALTED reason, the CMDB's summary.
    Task<QueryResult<IReadOnlyList<ConsoleLine>>> ConnectorLinesAsync(int hours, int top, CancellationToken ct);
}

public static class ConnectorLines
{
    /// What the connector engines print (engine\asset-cmdb\Invoke-SIVulnLoop.ps1 / Invoke-SICmdb.ps1). Fixed text.
    public static readonly IReadOnlyList<string> Needles = ["plan      :", "HALTED --", "submitted "];

    public const string Template = """
ContainerAppConsoleLogs
| where TimeGenerated > ago({{HOURS}}h)
| extend Group = tostring(column_ifexists("ContainerGroupName", "")), Line = tostring(column_ifexists("Log", column_ifexists("Message", "")))
| where {{MATCH}}
| project TimeGenerated, Group, Line
| order by TimeGenerated desc
| take {{TOP}}
""";

    public static string Build(int hours, int top) => QueryTemplates.Fill(Template, new Dictionary<string, string>
    {
        ["HOURS"] = Math.Clamp(hours, 1, 24 * 30).ToString(CultureInfo.InvariantCulture),
        ["MATCH"] = string.Join(" or ", Needles.Select(n => "Line contains " + QueryParameters.KqlString(n))),
        ["TOP"] = Math.Clamp(top, 1, 500).ToString(CultureInfo.InvariantCulture),
    });
}

public sealed class LogAnalyticsConsoleLogReader : IConsoleLogReader
{
    /// Columns differ between the resource-specific table and older shapes, so every one is read with column_ifexists.
    public const string Template = """
ContainerAppConsoleLogs
| where TimeGenerated > ago({{HOURS}}h)
| extend Group = tostring(column_ifexists("ContainerGroupName", "")), Job = tostring(column_ifexists("JobName", "")), Line = tostring(column_ifexists("Log", column_ifexists("Message", "")))
| where Job == {{JOB}} or Group startswith {{PREFIX}}
| where {{CONTAINS_ALL}} or Line contains {{CONTAINS}}
| project TimeGenerated, Group, Line
| order by TimeGenerated desc
| take {{TOP}}
""";

    private readonly ILogAnalyticsReader _la;
    public LogAnalyticsConsoleLogReader(ILogAnalyticsReader la) => _la = la;

    public static string Build(string job, string? execution, int hours, int top, string? contains)
    {
        var name = JobRules.Name(job);
        if (execution is not null && !JobRules.JobName().IsMatch(execution) && !Regex.IsMatch(execution, @"^[a-z0-9\-]{1,63}$")) throw new ArgumentException("not an execution name");
        var c = string.IsNullOrWhiteSpace(contains) ? null : contains.Trim();
        if (c is { Length: > 100 }) throw new ArgumentException("the text filter is longer than 100 characters");
        return QueryTemplates.Fill(Template, new Dictionary<string, string>
        {
            ["HOURS"] = Math.Clamp(hours, 1, 24 * 30).ToString(CultureInfo.InvariantCulture),
            ["JOB"] = QueryParameters.KqlString(name),
            ["PREFIX"] = QueryParameters.KqlString(execution ?? name + "-"),
            ["CONTAINS_ALL"] = c is null ? "true" : "false",
            ["CONTAINS"] = QueryParameters.KqlString(c ?? ""),
            ["TOP"] = Math.Clamp(top, 1, 2000).ToString(CultureInfo.InvariantCulture),
        });
    }

    public async Task<QueryResult<IReadOnlyList<ConsoleLine>>> ReadAsync(string job, string? execution, int hours, int top, string? contains, CancellationToken ct)
    {
        var kql = Build(job, execution, hours, top, contains);
        var rows = await _la.QueryAsync(kql, ct);
        return new QueryResult<IReadOnlyList<ConsoleLine>>(rows.Select(r => new ConsoleLine(Cell.Time(r, "TimeGenerated"), Cell.Str(r, "Group"), ConsoleLine.Clean(Cell.Str(r, "Line")))).ToList(),
            kql, _la.SourceName, DateTimeOffset.UtcNow);
    }

    public async Task<QueryResult<IReadOnlyList<ConsoleLine>>> ConnectorLinesAsync(int hours, int top, CancellationToken ct)
    {
        var kql = ConnectorLines.Build(hours, top);
        var rows = await _la.QueryAsync(kql, ct);
        return new QueryResult<IReadOnlyList<ConsoleLine>>(rows.Select(r => new ConsoleLine(Cell.Time(r, "TimeGenerated"), Cell.Str(r, "Group"), ConsoleLine.Clean(Cell.Str(r, "Line")))).ToList(),
            kql, _la.SourceName, DateTimeOffset.UtcNow);
    }
}

public sealed class NotConfiguredConsoleLogReader : IConsoleLogReader
{
    public Task<QueryResult<IReadOnlyList<ConsoleLine>>> ReadAsync(string job, string? execution, int hours, int top, string? contains, CancellationToken ct) =>
        Task.FromResult(new QueryResult<IReadOnlyList<ConsoleLine>>(Array.Empty<ConsoleLine>(), "(no workspace is configured -- Estate:WorkspaceId)", "not-configured", DateTimeOffset.UtcNow));

    public Task<QueryResult<IReadOnlyList<ConsoleLine>>> ConnectorLinesAsync(int hours, int top, CancellationToken ct) => ReadAsync("", null, hours, top, null, ct);
}
