using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.DataHealth;
using SI.Management.Web.Jobs;
using SI.Management.Web.Performance;
using SI.Management.Web.RunReports;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin;

/// One sized database on the page: what it runs, its space, its load of the last 7 days and the advice.
public sealed record PerfDatabaseCard(string Name, string Label, string? Sku, double? Capacity, long? UsedMb, long? MaxMb, IReadOnlyList<PerfLoadHour> Load,
    IReadOnlyDictionary<string, IReadOnlyList<PerfPoint>> Parts, PerfAdvice Advice, bool Changeable);

/// <summary>
/// Operations &gt; Performance (#757; owner 2026-10-18: "add performance and stats in si gui so customer can see it. new
/// page" / "so they can choose to scale up down"). What support pulled by hand per install, for the customer: the pipeline's
/// runs and each step's time, the run in progress, every source's collection state, the databases' and the web app's size and
/// load of the last 7 days with a recommendation, the jobs' sizes, and data health. It reads SQL only -- the load is what the
/// heartbeat job stores (cfg.PerfSample); the web app has no Azure right (CR8).
/// Readers see everything. An Admin asks for another size of the main database or the web app (the customer's setting, on
/// the audit trail); the UPDATER applies it, up or down -- at the next update, or now when a SuperAdmin starts it (the
/// updater is a lifecycle job: only a SuperAdmin starts it, as on Operations &gt; Jobs).
/// </summary>
public sealed class PerformanceModel : PageModel
{
    private readonly IPerformanceStore _store;
    private readonly IDataHealthStore _health;
    private readonly IRunReportsStore _reports;
    private readonly SettingsCatalog _catalog;
    private readonly SettingsWriter _writer;
    private readonly IJobsClient _jobs;
    private readonly JobsOptions _jobOpts;
    private readonly ILogger<PerformanceModel> _log;

    public PerformanceModel(IPerformanceStore store, IDataHealthStore health, IRunReportsStore reports, SettingsCatalog catalog, SettingsWriter writer,
        IJobsClient jobs, IOptions<JobsOptions> jobOpts, ILogger<PerformanceModel> log, ISummaryStep? summaryStep = null)
    { _store = store; _health = health; _reports = reports; _catalog = catalog; _writer = writer; _jobs = jobs; _jobOpts = jobOpts.Value; _log = log; _summaryStep = summaryStep; }

    private readonly ISummaryStep? _summaryStep;
    /// #636: false = the Risk Analysis Summary step is off -- its collection row is left out of the sources.
    public bool SummaryOn { get; internal set; } = true;

    public DateTime NowUtc { get; private set; } = DateTime.UtcNow;
    public PerformanceData Data { get; private set; } = PerformanceData.Empty;
    public string? Error { get; private set; }
    public IReadOnlyList<PerfStepTrend> Trends { get; private set; } = [];
    public PerfProgress? Progress { get; private set; }
    public IReadOnlyList<PerfSource> Sources { get; private set; } = [];
    public IReadOnlyList<RunReportRow> Incomplete { get; private set; } = [];
    /// #902: the reports SI held on purpose at their last complete result (never counted as not complete).
    public IReadOnlyList<RunReportRow> HeldReports { get; private set; } = [];
    public bool ReportsKnown { get; private set; }
    public DataHealthView Health { get; private set; } = DataHealthView.Missing0;
    public IReadOnlyList<PerfDatabaseCard> Databases { get; private set; } = [];
    public PerfSize? Web { get; private set; }
    public IReadOnlyList<PerfLoadHour> WebLoad { get; private set; } = [];
    public PerfAdvice? WebAdvice { get; private set; }
    public IReadOnlyList<PerfSize> JobSizes { get; private set; } = [];
    public PerfPrices Prices { get; private set; } = PerfPrices.None;

    /// The size control is offered only while the shipped settings know the setting the updater reads.
    public bool SqlChangeable => _catalog.Find(PerfSizing.SqlKey) is { SetupOnly: false };
    public bool WebChangeable => _catalog.Find(PerfSizing.WebCpuKey) is { SetupOnly: false } && _catalog.Find(PerfSizing.WebMemoryKey) is { SetupOnly: false };
    public string UpdaterJob => _jobOpts.UpdaterJobName;

    [BindProperty] public string? Target { get; set; }
    [BindProperty] public string? Value { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public static string DatabaseLabel(string name) => name switch { "pro" => "Main database", "data" => "Data database", "identity" => "Identity database", _ => name };

    public async Task OnGetAsync(CancellationToken ct)
    {
        NowUtc = DateTime.UtcNow;
        Prices = PerfPrices.Shipped();
        try { Data = await _store.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the performance figures could not be read");
            Error = "The performance figures could not be read from the Pro database: " + ex.Message;
        }
        try { Health = await _health.ReadAsync(null, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "data health could not be read for the performance page"); }
        try
        {
            var rr = await _reports.ReadAsync(null, ct);
            ReportsKnown = rr.HasTable;
            Incomplete = rr.Rows.Where(r => r.NotComplete).ToList();
            HeldReports = rr.Rows.Where(r => r.Held).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the Risk Analysis report verdicts could not be read for the performance page"); }
        try { SummaryOn = _summaryStep is null || await _summaryStep.IsOnAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the Summary step could not be read for the performance page"); }
        Build(NowUtc);
    }

    /// Everything the page shows, from what was read (PURE over Data; the tests call it through the page).
    internal void Build(DateTime nowUtc)
    {
        var d = Data;
        Trends = PerfRules.StepTrends(d.Runs, d.Steps, JobSchedule.Label);
        Progress = PerfRules.Progress(d.Runs, d.Steps, nowUtc, JobSchedule.Label);
        Sources = PerfRules.Sources(d.CollectionRows, PerfRules.RunningKeys(Progress, d.Steps), nowUtc, SummaryOn);

        var names = new List<string> { "pro" };
        names.AddRange(d.Sizes.Where(s => s.Kind == "database").Select(s => s.Name));
        names.AddRange(d.Series.Keys.Where(k => k.Kind == "database").Select(k => k.Name));
        var cards = new List<PerfDatabaseCard>();
        foreach (var n in names.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n switch { "pro" => 0, "data" => 1, "identity" => 2, _ => 3 }))
        {
            var size = d.Sizes.FirstOrDefault(s => s.Kind == "database" && s.Name.Equals(n, StringComparison.OrdinalIgnoreCase));
            var sku = n == "pro" && !string.IsNullOrWhiteSpace(d.Db.ServiceObjective) ? d.Db.ServiceObjective : size?.Sku;
            long? used = n == "pro" ? d.Db.UsedMb : null, max = n == "pro" ? d.Db.MaxMb : null;
            if (used is null && d.Series.TryGetValue(("database", n, "storage"), out var st) && st.LastOrDefault() is { } lastSt) used = (long?)((lastSt.Max ?? lastSt.Avg) / 1048576.0);
            if (max is null && size?.MaxBytes is { } mb) max = (long)(mb / 1048576.0);
            var load = PerfAdvisor.DatabaseLoad(d.Series, n);
            var parts = new Dictionary<string, IReadOnlyList<PerfPoint>>(StringComparer.Ordinal);
            foreach (var m in new[] { "dtu_consumption_percent", "cpu_percent", "physical_data_read_percent", "log_write_percent" })
                if (d.Series.TryGetValue(("database", n, m), out var pts)) parts[m] = pts;
            cards.Add(new PerfDatabaseCard(n, DatabaseLabel(n), sku, size?.Capacity, used, max, load, parts,
                PerfAdvisor.Database(n, DatabaseLabel(n), sku, load, d.PacingHighPercent), n == "pro" && SqlChangeable));
        }
        Databases = cards;

        Web = d.Sizes.FirstOrDefault(s => s.Kind == "webapp");
        var webName = Web?.Name ?? d.Series.Keys.FirstOrDefault(k => k.Kind == "webapp").Name;
        WebLoad = webName is null ? [] : PerfAdvisor.WebLoad(d.Series, webName, Web?.Cpu, Web?.MemoryGi);
        WebAdvice = PerfAdvisor.WebApp(webName ?? "web app", Web?.Cpu, Web?.MemoryGi, WebLoad);
        JobSizes = d.Sizes.Where(s => s.Kind == "job").ToList();
    }

    /// The database size asked for, and whether it is what the database runs now.
    public (PerfSizeRequest? Request, bool Applied) SqlRequest()
    {
        if (!Data.Requests.TryGetValue(PerfSizing.SqlKey, out var r)) return (null, false);
        var running = Databases.FirstOrDefault(c => c.Name == "pro")?.Sku;
        return (r, PerfSizing.SqlApplied(r.Value, running));
    }

    /// The web app size asked for (both parts), and whether it is what the web app runs now.
    public (string? Text, DateTime? At, string? By, bool Applied) WebRequest()
    {
        Data.Requests.TryGetValue(PerfSizing.WebCpuKey, out var c);
        Data.Requests.TryGetValue(PerfSizing.WebMemoryKey, out var m);
        if (c is null && m is null) return (null, null, null, false);
        double? rc = double.TryParse(c?.Value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var x) ? x : null;
        var rm = PerfSizing.ParseGi(m?.Value);
        var at = new[] { c?.AtUtc, m?.AtUtc }.Max();
        var by = (c?.AtUtc >= m?.AtUtc ? c?.By : m?.By) ?? c?.By ?? m?.By;
        var text = rc is { } a && rm is { } b ? PerfSizing.WebText(a, b) : (c?.Value ?? "?") + " CPU / " + (m?.Value ?? "?");
        return (text, at, by, PerfSizing.WebApplied(rc, rm, Web?.Cpu, Web?.MemoryGi));
    }

    /// An Admin asks for another size of the main database or the web app: the customer's setting is saved (on the audit
    /// trail and the change log); the updater applies it, up or down. Never below S1 / Basic; the web app at least 1 CPU / 2 GiB.
    [Audited("performance.size.request")]
    public async Task<IActionResult> OnPostSizeAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = AuditScope.Current;
        var target = (Target ?? "").Trim().ToLowerInvariant();
        if (audit is not null) { audit.Target = "/Admin/Performance/" + target; audit.Reason = string.IsNullOrWhiteSpace(Reason) ? null : Reason.Trim(); }
        try
        {
            var data = await _store.ReadAsync(ct);
            string message;
            if (target == "database")
            {
                if (!SqlChangeable) return Refused(audit, "The database size cannot be changed from here in this version yet -- it comes with a later update.");
                if (PerfSizing.ValidateSql(Value) is { } bad) return Refused(audit, bad);
                var v = PerfSizing.SqlLadder[PerfSizing.SqlIndex(Value)];
                var r = await Save(PerfSizing.SqlKey, PerfSizing.Json(_catalog.Find(PerfSizing.SqlKey)?.Type, PerfSizing.SqlDtu[v], v), data, ct);
                if (r.Status != WriteStatus.Saved) return Refused(audit, r.Message);
                message = $"The main database will run {v}. The updater applies it at the next update" + (User.IsSuperAdmin() ? " -- or now, with Apply now." : ".");
            }
            else if (target == "webapp")
            {
                if (!WebChangeable) return Refused(audit, "The web app's size cannot be changed from here in this version yet -- it comes with a later update.");
                var (opt, bad) = PerfSizing.ParseWeb(Value);
                if (opt is not { } o) return Refused(audit, bad ?? "Choose a size.");
                var r1 = await Save(PerfSizing.WebCpuKey, PerfSizing.Json(_catalog.Find(PerfSizing.WebCpuKey)?.Type, o.Cpu, o.Cpu.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)), data, ct);
                if (r1.Status != WriteStatus.Saved) return Refused(audit, r1.Message);
                var r2 = await Save(PerfSizing.WebMemoryKey, PerfSizing.Json(_catalog.Find(PerfSizing.WebMemoryKey)?.Type, o.MemoryGi, PerfSizing.MemoryText(o.MemoryGi)), data, ct);
                if (r2.Status != WriteStatus.Saved) return Refused(audit, r2.Message);
                message = $"The web app will run {PerfSizing.WebText(o.Cpu, o.MemoryGi)}. The updater applies it at the next update" + (User.IsSuperAdmin() ? " -- or now, with Apply now." : ".");
            }
            else return Refused(audit, "Choose the database or the web app.");
            return Toast(true, message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "a size request failed");
            audit?.Refused(ex.Message);
            return Toast(false, "Not saved: " + ex.Message);
        }
    }

    /// A SuperAdmin starts the updater now, so a size asked for is applied without waiting for the next update. The web app
    /// only STARTS the job (its start-only right on the named jobs, CR8); the updater changes Azure as its own identity.
    [Audited("performance.size.apply")]
    public async Task<IActionResult> OnPostApplyAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) audit.Target = "/Admin/Performance/apply";
        // the updater is a lifecycle job: only a SuperAdmin starts it (the same rule as Operations > Jobs)
        if (AccessLifecycle.IsLifecycleJob(UpdaterJob, _jobOpts) && !User.IsSuperAdmin())
            return Refused(audit, "Only a SuperAdmin starts the updater. The size asked for is applied at the next update.");
        try
        {
            var exec = await _jobs.StartAsync(UpdaterJob, ct);
            return Toast(true, $"The updater started ({exec}). It applies the sizes asked for; this page shows them as applied once it is done.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the updater could not be started from the performance page");
            audit?.Refused(ex.Message);
            return Toast(false, "The updater could not be started: " + ex.Message + ". The size asked for is applied at the next update.");
        }
    }

    private Task<WriteResult> Save(string key, System.Text.Json.JsonElement value, PerformanceData data, CancellationToken ct)
    {
        long? expected = data.Requests.TryGetValue(key, out var have) ? have.Version : null;
        var why = string.IsNullOrWhiteSpace(Reason) ? "size asked for on " + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/Performance") : Reason.Trim();
        return _writer.WriteAsync(new SettingWrite(key, "solution", "Set", value, null, expected, why.Length > 400 ? why[..400] : why), User.ChangeName(), ct);
    }

    private IActionResult Refused(AuditScope? audit, string message)
    {
        audit?.Refused(message);
        return Toast(false, message);
    }

    private IActionResult Toast(bool ok, string message)
    {
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage();
    }
}
