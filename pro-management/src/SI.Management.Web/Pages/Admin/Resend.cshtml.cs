using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.ChangeJournal;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Configuration &gt; Connectors &gt; Runs &gt; Resend and undo (#404 part 2: "people make mistakes or the platform goes down"). Admin.
/// SEND AN EARLIER COLLECTION AGAIN: the complete Risk Analysis collections of the last SIWeb_CollectionResendDays days
/// (default 3) -- read from what the Pro database already keeps, never copied again -- can be sent into a vulnerability
/// connector by hand. The connector's own job runs with that collection instead of the newest one, through its NORMAL
/// path: the same plan, the same guards (a close ceiling still holds a mass close), the same audit.
/// UNDO THE LAST RUN where the connector can reverse it: the SQL vulnerability connector records every state change of
/// every item per run (vuln.VulnerabilityEvent), so its newest applied run can be put back -- closes reopened, reopens
/// closed again, new items closed as "undone". ServiceNow and REST connectors keep no before-state SecurityInsight could
/// put back; the page says so plainly instead of offering a button that cannot work.
/// Both are a request (cfg.CollectionSend) the job carries out and records; both are audited.
/// </summary>
public sealed class ResendModel : PageModel
{
    private readonly ICollectionSendStore _store;
    private readonly ConfigSettings _settings;
    private readonly IJobsClient? _jobs;
    private readonly ILogger<ResendModel> _log;
    public ResendModel(ICollectionSendStore store, ConfigSettings settings, ILogger<ResendModel> log, IJobsClient? jobs = null)
    { _store = store; _settings = settings; _log = log; _jobs = jobs; }

    public const int ReasonMin = 10;

    [BindProperty] public string? Connector { get; set; }
    [BindProperty] public int CollectionId { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public bool HasTable { get; private set; }
    public string? Error { get; private set; }
    public int Days { get; private set; } = 3;
    public IReadOnlyList<SendConnector> Connectors { get; private set; } = Array.Empty<SendConnector>();
    public IReadOnlyList<SendCollection> Collections { get; private set; } = Array.Empty<SendCollection>();
    public IReadOnlyList<CollectionSend> Recent { get; private set; } = Array.Empty<CollectionSend>();
    public bool JobsConfigured => _jobs is { IsConfigured: true };

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            HasTable = await _store.ExistsAsync(ct);
            Days = (await _settings.ReadAsync(ct)).ResendDays;
            if (!HasTable) return;
            Connectors = await _store.ConnectorsAsync(ct);
            Collections = await _store.CollectionsAsync(Days, ct);
            Recent = await _store.RecentAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the resend page failed");
            Error = "The connectors and collections could not be read: " + ex.Message;
        }
    }

    private IActionResult Back(string message, bool ok)
    {
        TempData["toast"] = message; TempData["toastKind"] = ok ? "ok" : "error";
        return Redirect("/Admin/Resend");
    }

    private IActionResult Refused(string message) { AuditScope.Current?.Refused(message); return Back("Not sent: " + message, false); }

    private async Task<(SendConnector? C, string? Why)> ConnectorAsync(CancellationToken ct)
    {
        if (!await _store.ExistsAsync(ct)) return (null, "this database cannot record the request yet (apply sql\\si-pro-settings.sql -- it only adds)");
        var c = (await _store.ConnectorsAsync(ct)).FirstOrDefault(x => string.Equals(x.Name, Connector, StringComparison.Ordinal));
        if (c is null) return (null, "choose a vulnerability connector");
        if (!c.Enabled) return (null, $"{c.Name} is switched off -- switch it on in " + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/ConnectorSetup/Index") + " first");
        return (c, null);
    }

    private async Task<string> StartAsync(SendConnector c, long id, Dictionary<string, string> env, CancellationToken ct)
    {
        if (!JobsConfigured)
        {
            await _store.SetStateAsync(id, "refused", "the web app cannot start jobs in this installation (Jobs is not configured) -- nothing was sent", ct);
            throw new InvalidOperationException("the web app cannot start jobs in this installation, so nothing was sent");
        }
        env["SI_VulnSync_SendId"] = id.ToString(CultureInfo.InvariantCulture);
        env["SI_VulnSync_Connector"] = c.Name;
        try { return await _jobs!.StartWithEnvAsync(c.Job, env, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await _store.SetStateAsync(id, "failed", "the job could not be started: " + ex.Message, ct);
            throw new InvalidOperationException("the connector's job could not be started: " + ex.Message);
        }
    }

    /// "Send this collection to &lt;connector&gt;": the connector's job runs once with that collection, through its normal path and guards.
    [Audited("connector.collection.resend")]
    public async Task<IActionResult> OnPostResendAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        try
        {
            if (AuditScope.Current is { } a0) { a0.Target = "/Admin/Resend/connector/" + Connector; a0.Reason = Reason; }
            var why = (Reason ?? "").Trim();
            if (why.Length < ReasonMin) return Refused($"say why it is sent again (at least {ReasonMin} characters) -- it goes on the audit trail");
            var (c, bad) = await ConnectorAsync(ct);
            if (c is null) return Refused(bad!);
            var days = (await _settings.ReadAsync(ct)).ResendDays;
            var col = (await _store.CollectionsAsync(days, ct)).FirstOrDefault(x => x.CollectionId == CollectionId);
            if (col is null) return Refused($"choose a complete collection of the last {days} day(s)");
            var id = await _store.RequestAsync("resend", c, col, null, why, User.ChangeName(), AuditScope.Current?.CorrelationId, ct);
            var exec = await StartAsync(c, id, new Dictionary<string, string> { ["SI_VulnSync_CollectionTime"] = SqlCollectionSendStore.Iso(col.CollectionTime) }, ct);
            if (AuditScope.Current is { } a) a.AfterJson = JsonSerializer.Serialize(new { request = id, connector = c.Name, kind = c.Kind, collection = SqlCollectionSendStore.Iso(col.CollectionTime), rows = col.Rows, partial = col.Partial, job = c.Job, execution = exec, mode = c.Mode });
            return Back($"Sent: {c.Job} runs {c.Name} once with the collection of {Fmt.When(col.CollectionTime)} ({exec}). Its guards still apply{(c.Mode == "apply" ? "" : " -- the connector is in whatif, so it only plans and reports")}. The outcome appears below.", true);
        }
        catch (InvalidOperationException ex) { return Refused(ex.Message); }
    }

    /// "Undo the last run into &lt;connector&gt;" -- only where the connector can reverse it (the SQL vulnerability connector).
    [Audited("connector.run.undo")]
    public async Task<IActionResult> OnPostUndoAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        try
        {
            if (AuditScope.Current is { } a0) { a0.Target = "/Admin/Resend/connector/" + Connector; a0.Reason = Reason; }
            var why = (Reason ?? "").Trim();
            if (why.Length < ReasonMin) return Refused($"say why the run is undone (at least {ReasonMin} characters) -- it goes on the audit trail");
            var (c, bad) = await ConnectorAsync(ct);
            if (c is null) return Refused(bad!);
            if (c.CannotUndo is { } no) return Refused($"{c.Name} cannot be undone: {no}");
            var id = await _store.RequestAsync("undo", c, null, c.LastRunId, why, User.ChangeName(), AuditScope.Current?.CorrelationId, ct);
            var exec = await StartAsync(c, id, new Dictionary<string, string> { ["SI_VulnSync_UndoRunId"] = c.LastRunId! }, ct);
            if (AuditScope.Current is { } a) a.AfterJson = JsonSerializer.Serialize(new { request = id, connector = c.Name, run = c.LastRunId, opened = c.Opened, reopened = c.Reopened, closed = c.Closed, job = c.Job, execution = exec });
            return Back($"Undo started: {c.Job} puts back what run {c.LastRunId} changed in {c.Name} ({exec}). Items changed again since that run are left as they are and listed in the outcome.", true);
        }
        catch (InvalidOperationException ex) { return Refused(ex.Message); }
    }
}
