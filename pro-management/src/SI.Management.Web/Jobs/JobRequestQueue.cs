using System.Net;
using System.Net.Http.Headers;
using System.Security;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Azure.Core;
using SI.Management.Web.Data;

namespace SI.Management.Web.Jobs;

/// <summary>
/// #1252 (SECURE-WEB-1 part 2; owner 2026-11-25 "Build queue fix now"): the web app holds NO right on any job (since 3.1.18).
/// A start a person asks for -- Run now (the pipeline, a stage, a step, one job), Stop (the runner started with the cancel),
/// the runner's wake-up after a schedule / enable change (a cfg.JobTriggerRequest row it applies), a template release, a
/// mail "send now" -- is ONE message on the queue si-job-requests of the install's storage account, sent with the web app's
/// managed identity (its one right there: Storage Queue Data Message Sender on that queue only; Microsoft's Queue service
/// REST API, no SDK, no key, no SAS). caj-si-job-requests, started by that queue as the ENGINE identity, checks the message
/// (one of this install's jobs, only the names allowed for that job, not older than 15 minutes) and starts the job
/// (engine/job-requests/SI-JobRequests.ps1). The updater sets cfg.InstallState 'JobRequestQueue' to the queue's address
/// ONLY after the queue, the job's queue trigger and the web app's right read back; until then the buttons work as before.
/// </summary>
public interface IJobRequestQueue
{
    /// The queue's address, or null while the install has none (the buttons then work as before). Cached for a minute.
    Task<Uri?> QueueAsync(CancellationToken ct);
    /// Puts one message on the queue; returns the queue's message id. Throws InvalidOperationException with plain words.
    Task<string> SendAsync(Uri queue, string text, CancellationToken ct);
}

public sealed class JobRequestQueue : IJobRequestQueue
{
    public const string RowSql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'JobRequestQueue';
""";
    public const string QueueName = "si-job-requests";
    internal const string ApiVersion = "2021-08-06";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly TimeSpan CacheFor = TimeSpan.FromMinutes(1);

    private readonly ISqlExecutor _sql;
    private readonly TokenCredential _cred;
    private readonly HttpMessageInvoker _http;
    private readonly object _gate = new();
    private (Uri? Queue, DateTimeOffset At)? _cached;

    public JobRequestQueue(ISqlExecutor sql, TokenCredential cred) : this(sql, cred, null) { }
    public JobRequestQueue(ISqlExecutor sql, TokenCredential cred, HttpMessageInvoker? http) { _sql = sql; _cred = cred; _http = http ?? Http; }

    /// PURE. The queue address the updater recorded, checked: https, a Queue service host (public or sovereign cloud), the
    /// path exactly /si-job-requests, no query. Anything else = null (the buttons work as before).
    public static Uri? ParseQueueUri(string? value)
    {
        if (!Uri.TryCreate((value ?? "").Trim(), UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return null;
        if (!string.IsNullOrEmpty(u.Query) || !string.IsNullOrEmpty(u.Fragment) || !string.IsNullOrEmpty(u.UserInfo) || !u.IsDefaultPort) return null;
        var h = u.Host;
        if (!(h.EndsWith(".queue.core.windows.net", StringComparison.OrdinalIgnoreCase) || h.EndsWith(".queue.core.usgovcloudapi.net", StringComparison.OrdinalIgnoreCase)
              || h.EndsWith(".queue.core.chinacloudapi.cn", StringComparison.OrdinalIgnoreCase))) return null;
        return string.Equals(u.AbsolutePath.TrimEnd('/'), "/" + QueueName, StringComparison.Ordinal) ? u : null;
    }

    public async Task<Uri?> QueueAsync(CancellationToken ct)
    {
        lock (_gate) { if (_cached is { } c && DateTimeOffset.UtcNow - c.At < CacheFor) return c.Queue; }
        Uri? q = null;
        try
        {
            var rows = await _sql.QueryAsync(RowSql, new Dictionary<string, object?>(), ct);
            q = ParseQueueUri(rows.FirstOrDefault(r => r.ContainsKey("Value"))?.Str("Value"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { q = null; }   // no row / older schema: as before
        lock (_gate) { _cached = (q, DateTimeOffset.UtcNow); }
        return q;
    }

    /// PURE. The Put Message body: the request's raw JSON as the message text (XML-escaped; never base64).
    public static string Body(string text) => "<QueueMessage><MessageText>" + SecurityElement.Escape(text) + "</MessageText></QueueMessage>";

    public async Task<string> SendAsync(Uri queue, string text, CancellationToken ct)
    {
        var token = await _cred.GetTokenAsync(new TokenRequestContext(["https://storage.azure.com/.default"]), ct);
        // the message lives at most 15 minutes: the job refuses an older one anyway, so nobody's old click starts a job later
        using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(queue.AbsoluteUri.TrimEnd('/') + "/messages?messagettl=900"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        req.Headers.Add("x-ms-version", ApiVersion);
        req.Headers.Add("x-ms-date", DateTime.UtcNow.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
        req.Content = new StringContent(Body(text), new UTF8Encoding(false), "application/xml");
        using var res = await _http.SendAsync(req, ct);
        if (res.StatusCode == HttpStatusCode.Forbidden)
            throw new InvalidOperationException("the request queue did not accept the request yet (HTTP 403) -- after an update the web app's right on the queue takes up to 10 minutes to apply; try again in a few minutes, nothing was started");
        if (!res.IsSuccessStatusCode)
            throw new InvalidOperationException($"the request queue answered HTTP {(int)res.StatusCode} -- nothing was started; try again");
        var body = await res.Content.ReadAsStringAsync(ct);
        try { return XDocument.Parse(body).Descendants("MessageId").FirstOrDefault()?.Value ?? ""; }
        catch (System.Xml.XmlException) { return ""; }
    }
}

/// <summary>
/// #1252: the starts of the web app as REQUESTS on the job request queue (see JobRequestQueue). Reads (the job list, the
/// executions) go to the inner client (the web app's Container Apps Jobs Reader). A trigger change is never made here --
/// it is a cfg.JobTriggerRequest row (RequestedTriggerJobsClient, above this client) whose runner wake-up comes back here as
/// a start of caj-si-flow. The same checks as a direct start run first (a job the list shows, valid names), so a request
/// that cannot be started is refused on the page; the job request job checks everything again.
/// </summary>
public sealed class QueuedStartJobsClient : IJobsClient
{
    private readonly IJobsClient _reads;
    private readonly IJobRequestQueue _queue;
    private readonly Uri _at;

    public QueuedStartJobsClient(IJobsClient reads, IJobRequestQueue queue, Uri at) { _reads = reads; _queue = queue; _at = at; }

    public bool IsConfigured => _reads.IsConfigured;
    public Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct) => _reads.ListAsync(ct);
    public Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct) => _reads.ExecutionsAsync(job, top, ct);
    public Task<string> StartAsync(string job, CancellationToken ct) => StartWithEnvAsync(job, new Dictionary<string, string>(), ct);

    public async Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct)
    {
        var name = JobRules.Name(job);
        if (!(await _reads.ListAsync(ct)).Any(j => j.Name == name)) throw new ArgumentException($"'{name}' is not one of this installation's jobs");
        var id = Guid.NewGuid().ToString("N")[..12];
        var by = SI.Management.Web.Audit.AuditScope.Current?.Actor is { Length: > 0 } a ? a : "web app";
        var text = Message(name, env, id, by);
        await _queue.SendAsync(_at, text, ct);
        return RequestedText(id);
    }

    /// #1391: the ONLY names outside the upper-case shape a request may carry -- exactly the four the Resend page
    /// (Pages/Admin/Resend.cshtml.cs) sends to the connector's job, by name, never a pattern. The job request job lists the
    /// same four ($script:SIJobRequestsExactNames in engine/job-requests/SI-JobRequests.ps1).
    public static readonly IReadOnlyList<string> ResendNames = ["SI_VulnSync_SendId", "SI_VulnSync_Connector", "SI_VulnSync_CollectionTime", "SI_VulnSync_UndoRunId"];

    /// PURE. The message the job request job reads (raw JSON, the keys of engine/job-requests/SI-JobRequests.ps1).
    public static string Message(string job, IReadOnlyDictionary<string, string> env, string id, string by)
    {
        var e = new JsonObject();
        foreach (var kv in env.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            if (!JobRules.EnvName().IsMatch(kv.Key) && !ResendNames.Contains(kv.Key, StringComparer.Ordinal)) throw new ArgumentException($"'{kv.Key}' is not an environment variable name");
            if ((kv.Value ?? "").Length > 1000) throw new ArgumentException($"the value of {kv.Key} is longer than 1000 characters");
            e[kv.Key] = kv.Value ?? "";
        }
        var o = new JsonObject
        {
            ["SI_JOBREQ_ACTION"] = "start", ["SI_JOBREQ_JOB"] = job, ["SI_JOBREQ_ENV"] = e, ["SI_JOBREQ_ID"] = id,
            ["SI_AUDIT_STARTED_BY"] = by.Length > 256 ? by[..256] : by,
        };
        var s = o.ToJsonString();
        return Encoding.UTF8.GetByteCount(s) <= 8192 ? s : throw new ArgumentException("the start's values are too long");
    }

    public const string RequestedPrefix = "requested";

    /// PURE. What a start answers: it is REQUESTED, the job request job starts it (said where "execution ..." was).
    public static string RequestedText(string id) => $"{RequestedPrefix} (request {id}) -- it starts within a minute; the job list shows it then";

    /// PURE. Is this a start's answer from the queue (not an execution name)?
    public static bool IsRequested(string? s) => (s ?? "").StartsWith(RequestedPrefix + " (request ", StringComparison.Ordinal);

    /// PURE. A start's answer in words: "execution <name>" for a start made, the request's own words for one requested.
    public static string Said(string? exec) => IsRequested(exec) ? exec! : "execution " + exec;

    public Task SetCronAsync(string job, string cron, CancellationToken ct) => throw NotHere();
    public Task DisableAsync(string job, CancellationToken ct) => throw NotHere();
    public Task EnableAsync(string job, CancellationToken ct) => throw NotHere();
    public Task ScheduleAsync(string job, string cron, CancellationToken ct) => throw NotHere();
    private static InvalidOperationException NotHere() => new("a job's schedule is changed by the pipeline job (a request it applies) -- never by the web app");
}

/// <summary>
/// #1252: per call, the job request queue when the install has one (cfg.InstallState 'JobRequestQueue', read back by the
/// updater), else the client as before. Built per request (transient), so the state is read once per page action.
/// </summary>
public sealed class JobRequestSwitchJobsClient : IJobsClient
{
    private readonly IJobsClient _before;
    private readonly IJobRequestQueue _queue;
    private readonly Func<Uri, IJobsClient> _queued;
    private IJobsClient? _chosen;

    public JobRequestSwitchJobsClient(IJobsClient before, IJobRequestQueue queue, Func<Uri, IJobsClient> queued) { _before = before; _queue = queue; _queued = queued; }

    private async Task<IJobsClient> PickAsync(CancellationToken ct)
    {
        if (_chosen is not null) return _chosen;
        var q = await _queue.QueueAsync(ct);
        _chosen = q is null ? _before : _queued(q);
        return _chosen;
    }

    public bool IsConfigured => _before.IsConfigured;
    public IReadOnlyList<string> RequestedTriggerChanges => (_chosen ?? _before).RequestedTriggerChanges;
    public async Task<IReadOnlyList<JobInfo>> ListAsync(CancellationToken ct) => await (await PickAsync(ct)).ListAsync(ct);
    public async Task<IReadOnlyList<JobExecution>> ExecutionsAsync(string job, int top, CancellationToken ct) => await (await PickAsync(ct)).ExecutionsAsync(job, top, ct);
    public async Task<string> StartAsync(string job, CancellationToken ct) => await (await PickAsync(ct)).StartAsync(job, ct);
    public async Task<string> StartWithEnvAsync(string job, IReadOnlyDictionary<string, string> env, CancellationToken ct) => await (await PickAsync(ct)).StartWithEnvAsync(job, env, ct);
    public async Task SetCronAsync(string job, string cron, CancellationToken ct) => await (await PickAsync(ct)).SetCronAsync(job, cron, ct);
    public async Task DisableAsync(string job, CancellationToken ct) => await (await PickAsync(ct)).DisableAsync(job, ct);
    public async Task EnableAsync(string job, CancellationToken ct) => await (await PickAsync(ct)).EnableAsync(job, ct);
    public async Task ScheduleAsync(string job, string cron, CancellationToken ct) => await (await PickAsync(ct)).ScheduleAsync(job, cron, ct);
}
