using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Web.Auth;
using SI.Management.Web.Columns;
using SI.Management.Web.Data;
using SI.Management.Web.DataQuality;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Operations > Data quality (REQUIREMENTS #577 step 2): per pipeline run the verdict (anomaly detected yes / no, the
/// largest change against the expected range), the most significant changes, every warning in full (what changed, the 3
/// earlier values and today's, the likely cause from the settings changes -- each linked to the audit trail --, what to do
/// and Re-run from here; the fields of ONE source that are filled less at once are ONE warning with the fields listed
/// inside it), whether the run's mail went out and, if not, why (a mail goes out only when the warnings change), every key number of the run with its trend over the runs before, and the history of runs (pick
/// one to see what it warned about). A WARNING only: nothing here holds or blocks anything.
/// Readers see it. Re-run from here is the pipeline's own "re-run from a step" (Operations > Jobs): Admin, asked first,
/// queued by the same code, on the audit trail -- it answers in place with a toast.
/// The three lists (changes, key numbers, history) are the shared page table: the column chooser, each person's layout
/// and the all-rows exports.
/// </summary>
public sealed class DataQualityModel : DataViewPageModel
{
    private readonly IDataQualityStore _store;
    private readonly IJobsClient _jobs;
    private readonly IFlowStore _flow;
    private readonly ISqlExecutor _sql;
    private readonly IConfiguration _config;
    private readonly ILogger<DataQualityModel> _log;

    public DataQualityModel(IDataQualityStore store, IJobsClient jobs, IFlowStore flow, ISqlExecutor sql, IConfiguration config, ILogger<DataQualityModel> log)
    { _store = store; _jobs = jobs; _flow = flow; _sql = sql; _config = config; _log = log; }

    /// How many runs the history lists (a choice, never a limit on what exists: a longer history is one click).
    public static readonly int[] HistoryChoices = [30, 90, 365];
    /// How many runs each key number's trend covers: the picked run and the ones before it.
    public const int TrendRuns = 14;

    /// The run to look at (its id; none = the newest).
    [BindProperty(SupportsGet = true)] public string? Run { get; set; }
    /// How many runs the history lists.
    [BindProperty(SupportsGet = true)] public int History { get; set; } = 30;
    /// The group of key numbers shown (none = every group).
    [BindProperty(SupportsGet = true)] public string? Group { get; set; }
    /// Re-run from here: the pipeline step.
    [BindProperty] public string? Step { get; set; }

    public DataQualityView View { get; private set; } = DataQualityView.Missing;
    /// Every key number of the picked run (all groups).
    public IReadOnlyList<DataQualityNumber> Numbers { get; private set; } = Array.Empty<DataQualityNumber>();
    public string? Error { get; private set; }
    /// The viewer's regional number format (the same as every other page, Fmt).
    public CultureInfo Culture => SI.Management.Core.ProData.ScoreFormat.Culture;
    /// Whether this person may open the audit trail (a change is linked to it only then).
    public bool CanOpenAuditTrail => SI.Management.Web.Audit.AuditVisibility.Of(User) is not null;

    /// The group picked, when it is one the run has numbers of.
    public string? ActiveGroup => Group is { Length: > 0 } g && Numbers.Any(n => string.Equals(n.Group, g, StringComparison.OrdinalIgnoreCase))
        ? Numbers.First(n => string.Equals(n.Group, g, StringComparison.OrdinalIgnoreCase)).Group : null;

    /// Show fields that are never filled (address parameter "never=true"; off = they are hidden, the standard).
    [BindProperty(SupportsGet = true, Name = "never")] public bool ShowNeverFilled { get; set; }

    /// <summary>
    /// A field of a source that reads 0 % in this run AND in every earlier run the page has of it (its trend): a mapped
    /// field the source never delivers in this tenant. Such a row is hidden from the key numbers unless the switch is on.
    /// It never warns either way (a fill that was never above 0 cannot drop); a field that is outside its range is never
    /// one of these.
    /// </summary>
    public static bool NeverFilled(DataQualityNumber n) =>
        n.Group == DataQualityText.GroupFieldFill && n.Status != DataQualityNumber.Outside && n.Now == 0 && n.Trend.All(v => v is null || v.Value == 0);

    /// The key numbers the switch leaves: all with it on, else without the fields that are never filled.
    private IEnumerable<DataQualityNumber> Visible => ShowNeverFilled ? Numbers : Numbers.Where(n => !NeverFilled(n));

    /// How many fields are never filled in the picked group (or in all groups).
    public int NeverFilledCount => (ActiveGroup is { } g ? Numbers.Where(n => n.Group == g) : Numbers).Count(NeverFilled);

    /// How many key numbers are listed with the switch as it is, all groups.
    public int VisibleCount => Visible.Count();

    /// The key numbers listed: the picked group's, else all -- without the fields that are never filled unless asked for.
    public IReadOnlyList<DataQualityNumber> ShownNumbers => (ActiveGroup is { } g ? Visible.Where(n => n.Group == g) : Visible).ToList();

    /// The groups the run has numbers of, in the panel's order, with how many numbers are shown, how many there are, and
    /// how many are outside their range.
    public IReadOnlyList<(string Group, int Count, int Outside, int Shown)> GroupCounts => Numbers.GroupBy(n => n.Group)
        .OrderBy(g => DataQualityText.GroupOrder(g.Key))
        .Select(g => (g.Key, g.Count(), g.Count(n => n.Status == DataQualityNumber.Outside), ShowNeverFilled ? g.Count() : g.Count(n => !NeverFilled(n)))).ToList();

    /// A tab's count: "12" when every number is shown, "3 of 12" when some are hidden.
    public static string CountWords(int shown, int total) => shown == total ? Fmt.Int(total) : Fmt.Int(shown) + " of " + Fmt.Int(total);

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    private async Task LoadAsync(CancellationToken ct)
    {
        History = Fmt.Pick(History, HistoryChoices[0], HistoryChoices);
        try
        {
            View = await _store.ReadAsync(Run, History, TrendRuns, ct);
            if (View.Selected is { } run) Numbers = DataQualityMath.Numbers(run, View.Detail);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "data quality: the fingerprint could not be read");
            Error = "The data-quality runs could not be read: " + ex.Message;
        }
    }

    /// This page on a run, a group, the history length and the "fields that are never filled" switch (what is not given
    /// stays as it is).
    public string Link(string? run, string? group, int? history = null, bool? never = null)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(run)) parts.Add("run=" + Uri.EscapeDataString(run));
        if (!string.IsNullOrWhiteSpace(group)) parts.Add("group=" + Uri.EscapeDataString(group));
        var h = history ?? History;
        if (h != HistoryChoices[0]) parts.Add("history=" + h.ToString(CultureInfo.InvariantCulture));
        if (never ?? ShowNeverFilled) parts.Add("never=true");
        return "/Admin/DataQuality" + (parts.Count == 0 ? "" : "?" + string.Join("&", parts));
    }

    // ---- the three lists as the shared page table: the chooser, each person's layout, the all-rows exports ----

    protected override Task LoadForExportAsync(CancellationToken ct) => LoadAsync(ct);

    protected override IReadOnlyList<DataTable> BuildTables()
    {
        if (!View.HasTables) return Array.Empty<DataTable>();
        var c = Culture;
        var tables = new List<DataTable>();
        if (View.Selected is not null)
        {
            if (View.Detail.Anomalies.Count > 0) tables.Add(ChangesTable(View.Detail, Numbers, c));
            if (Numbers.Count > 0) tables.Add(NumbersTable(ShownNumbers, c));
        }
        if (View.Recent.Count > 0) tables.Add(RunsTable(View.Recent, c));
        return tables;
    }

    private static DataTable ChangesTable(DataQualityDetail detail, IReadOnlyList<DataQualityNumber> numbers, CultureInfo c)
    {
        static DataQualityAnomaly A(object o) => (DataQualityAnomaly)o;
        var trend = numbers.GroupBy(n => n.MetricKey, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Trend, StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<double?> TrendOf(DataQualityAnomaly a) => trend.TryGetValue(a.MetricKey, out var t) ? t : Array.Empty<double?>();
        var table = new DataTable
        {
            Id = "changes", View = "dataquality-changes", Title = "Data quality - most significant changes", Marker = "data-dq-anomalies",
            Rows = detail.Anomalies.Cast<object>().ToList(), Empty = "No key number is outside its expected range.",
            RowAttributes = o => new Dictionary<string, string?> { ["data-key"] = A(o).MetricKey, ["data-direction"] = A(o).Direction, ["data-rule"] = A(o).Rule },
            Columns =
            [
                new("KeyNumber", "Key number", o => A(o).Label, Link: o => "#w-" + Anchor(A(o).MetricKey), Description: "The key number that is outside its expected range; the link opens its warning below."),
                new("Group", "Group", o => DataQualityText.Group(A(o).MetricKey, A(o).Kind), Shown: false),
                new("WhatChanged", "What changed", o => DataQualityText.Rule(A(o).Rule)),
                new("Earlier", "Expected (the 3 runs before)", o => DataQualityText.Expected(A(o), CultureInfo.InvariantCulture), Text: o => DataQualityText.Expected(A(o), c),
                    Description: "The values of the three runs before this one, oldest first."),
                new("Expected", "Expected value (median)", o => A(o).Expected, Number: true, Shown: false, Text: o => DataQualityText.Number(A(o).Expected, A(o).Kind, c)),
                new("Now", "Now", o => A(o).Now, Number: true, Text: o => DataQualityText.Number(A(o).Now, A(o).Kind, c)),
                new("Change", "Change", o => A(o).ChangePct, Number: true, Text: o => DataQualityText.Change(A(o), c),
                    Description: "Against the expected value: percent (assets, report rows), points (a fill), percent of all active CIs (a tier, an asset class, CIs to retire)."),
                new("Trend", "Trend", o => TrendText(TrendOf(A(o)), A(o).Kind, CultureInfo.InvariantCulture), Text: o => TrendText(TrendOf(A(o)), A(o).Kind, c),
                    Description: "The number over the runs before this one, oldest first."),
                new("Cause", "Likely cause", o => A(o).Cause),
                new("Fields", "Fields", o => DataQualityText.FieldNames(detail.FieldsOf(A(o))), Shown: false,
                    Description: "For one warning about a source that fills many fields less at once: the fields. Each is listed with its values in the warning below."),
                new("Fix", "What to do", o => DataQualityText.Fix(A(o).Rule), Shown: false),
                new("Step", "Re-run from", o => DataQualityText.Step(A(o).Step), Shown: false),
                new("Direction", "Direction", o => A(o).Direction, Shown: false),
                new("Key", "Key", o => A(o).MetricKey, Shown: false),
            ],
        };
        table.Html["Trend"] = o => SparkHtml(TrendOf(A(o)), A(o).Kind, A(o).Label, c);
        table.Html["Change"] = o => new HtmlString("<span class=\"" + (A(o).Direction == "drop" ? "down" : "up") + "\">" + WebUtility.HtmlEncode(DataQualityText.Change(A(o), c)) + "</span>");
        return table;
    }

    private static DataTable NumbersTable(IReadOnlyList<DataQualityNumber> rows, CultureInfo c)
    {
        static DataQualityNumber N(object o) => (DataQualityNumber)o;
        var table = new DataTable
        {
            Id = "numbers", View = "dataquality-numbers", Title = "Data quality - key numbers", Marker = "data-dq-numbers",
            Rows = rows.Cast<object>().ToList(), Empty = "This run measured no key number.",
            RowAttributes = o => new Dictionary<string, string?> { ["data-key"] = N(o).MetricKey, ["data-status"] = N(o).Status },
            Columns =
            [
                new("Group", "Group", o => N(o).Group),
                new("KeyNumber", "Key number", o => N(o).Label),
                new("Now", "Now", o => N(o).Now, Number: true, Text: o => DataQualityText.Number(N(o).Now, N(o).Kind, c)),
                new("Earlier", "The 3 runs before", o => DataQualityText.Earlier(N(o).Earlier, N(o).Kind, CultureInfo.InvariantCulture), Text: o => DataQualityText.Earlier(N(o).Earlier, N(o).Kind, c),
                    Description: "The values of the (up to) three runs before this one, oldest first. With fewer than three there is no expected range yet."),
                new("Expected", "Expected value (median)", o => N(o).Expected, Number: true, Text: o => N(o).Expected is null ? "" : DataQualityText.Number(N(o).Expected, N(o).Kind, c)),
                new("Change", "Change", o => N(o).Change, Number: true, Text: o => N(o).Change is null ? "" : DataQualityText.Change(N(o).Kind, N(o).Change, c)),
                new("Status", "Range", o => DataQualityText.Status(N(o).Status)),
                new("Trend", "Trend", o => TrendText(N(o).Trend, N(o).Kind, CultureInfo.InvariantCulture), Text: o => TrendText(N(o).Trend, N(o).Kind, c),
                    Description: "The number over the runs before this one, oldest first."),
                new("Step", "Produced by", o => DataQualityText.Step(N(o).Step), Shown: false),
                new("Key", "Key", o => N(o).MetricKey, Shown: false),
            ],
        };
        table.Html["Trend"] = o => SparkHtml(N(o).Trend, N(o).Kind, N(o).Label, c);
        table.Html["Status"] = o => new HtmlString("<span class=\"badge " + (N(o).Status == DataQualityNumber.Outside ? "warn" : N(o).Status == DataQualityNumber.Within ? "good" : "info") + "\">"
            + WebUtility.HtmlEncode(DataQualityText.Status(N(o).Status)) + "</span>");
        return table;
    }

    private DataTable RunsTable(IReadOnlyList<DataQualityRun> rows, CultureInfo c)
    {
        static DataQualityRun R(object o) => (DataQualityRun)o;
        return new DataTable
        {
            Id = "runs", View = "dataquality-runs", Title = "Data quality - runs", Marker = "data-dq-runs",
            Rows = rows.Cast<object>().ToList(), Empty = "No run has been measured yet.",
            RowAttributes = o => new Dictionary<string, string?> { ["data-run"] = R(o).RunId, ["data-picked"] = View.Selected?.RunId == R(o).RunId ? "1" : null },
            Columns =
            [
                new("Measured", "Measured", o => R(o).ComputedAt, Link: o => Link(R(o).RunId, null), Description: "When the run's key numbers were measured; the link shows that run above."),
                new("Collection", "Risk Analysis collection", o => R(o).CollectionTime),
                new("Verdict", "Verdict", o => DataQualityText.Verdict(R(o), CultureInfo.InvariantCulture), Text: o => DataQualityText.Verdict(R(o), c)),
                new("KeyNumbers", "Key numbers", o => R(o).Metrics, Number: true),
                new("Outside", "Warnings", o => R(o).Anomalies, Number: true,
                    Description: "How many warnings the run has. The fields of one source that are filled less at once are one warning."),
                new("Largest", "Largest change", o => R(o).LargestDeltaPct, Number: true, Text: o => R(o).LargestDeltaPct is { } d ? Fmt.Signed(d, 0) : "",
                    Description: "The largest change of the run against its expected value (percent, or points for a fill)."),
                new("EarlierRuns", "Earlier runs", o => R(o).EarlierRuns, Number: true, Shown: false),
                new("Mail", "Mail", o => DataQualityText.Mail(R(o)),
                    Description: "Whether the run's data-quality mail went out. A mail goes out only when the numbers outside their range change, and at most once a day."),
                new("MailedAt", "Mailed", o => R(o).MailedAt, Shown: false),
                new("RunId", "Run id", o => R(o).RunId, Shown: false),
            ],
        };
    }

    /// An element id made of a key number's key.
    public static string Anchor(string key) => new(key.Select(ch => char.IsAsciiLetterOrDigit(ch) ? ch : '-').ToArray());

    /// A trend as text (the export, and the words under the line): the values, oldest first; a run that did not measure the number is "–".
    public static string TrendText(IReadOnlyList<double?> values, string kind, CultureInfo c) =>
        values.Count == 0 ? "" : string.Join(" / ", values.Select(v => DataQualityText.Number(v, kind, c)));

    /// A small trend line (inline SVG, no script, no style): the number over the runs, the newest marked.
    public static IHtmlContent SparkHtml(IReadOnlyList<double?> values, string kind, string label, CultureInfo c)
    {
        if (DataQualityText.Spark(values) is not { } s)
            return new HtmlString("<span class=\"muted small\" data-dq-spark-none>" + WebUtility.HtmlEncode(values.Count(v => v is not null) == 0 ? "" : "first run") + "</span>");
        static string R(double v) => v.ToString("0.##", CultureInfo.InvariantCulture);
        var words = label + " over the last " + s.Points.ToString(CultureInfo.InvariantCulture) + " runs: lowest " + DataQualityText.Number(s.Min, kind, c)
            + ", highest " + DataQualityText.Number(s.Max, kind, c) + ", now " + DataQualityText.Number(values.LastOrDefault(v => v is not null), kind, c) + ".";
        return new HtmlString("<svg class=\"dq-spark\" width=\"" + R(DataQualitySpark.Width) + "\" height=\"" + R(DataQualitySpark.Height) + "\" viewBox=\"0 0 " + R(DataQualitySpark.Width) + " " + R(DataQualitySpark.Height)
            + "\" role=\"img\" data-dq-spark=\"" + s.Points.ToString(CultureInfo.InvariantCulture) + "\" aria-label=\"" + WebUtility.HtmlEncode(words) + "\"><title>" + WebUtility.HtmlEncode(words)
            + "</title><path class=\"spark-line\" d=\"" + s.Path + "\" /><circle class=\"spark-now\" cx=\"" + R(s.LastX) + "\" cy=\"" + R(s.LastY) + "\" r=\"2.2\" /></svg>");
    }

    // ---- Re-run from here: the pipeline's own "re-run from a step" (Operations > Jobs), in place ----

    /// <summary>
    /// Queues "the pipeline from this step on" -- the same request, queue and runner start as Re-run from here on
    /// Operations > Jobs (<see cref="PipelineRequests"/>), Admin like it, on the audit trail like it. A request that asks
    /// for JSON (the page's script) is answered with the words for a toast, so the button stays where it is; a plain form
    /// post is answered with the page and the same words.
    /// </summary>
    [SI.Management.Web.Audit.Audited("job.flow.start")]
    public async Task<IActionResult> OnPostRerunAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        string message;
        var kind = "ok";
        try
        {
            var step = JobSchedule.Key(Step ?? "");
            if (step.Length == 0) throw new ArgumentException("this warning names no step to re-run from");
            if (!_jobs.IsConfigured) throw new InvalidOperationException(NotConfiguredJobsClient.Why);
            var jobs = await _jobs.ListAsync(ct);
            if (!jobs.Any(j => j.Name == JobFlow.FlowJob)) throw new InvalidOperationException($"this installation has no {JobFlow.FlowJob} job -- run setup (Bootstrap) once to create it");
            var stored = await _flow.ReadAsync(ct);
            var flow = stored.Definition ?? JobFlow.Default(jobs.Select(j => j.Name), _config["SI_Pipeline_StartTime"], _config["SI_Pipeline_TimeZone"]);
            if (!flow.Steps.Any(s => s.Job == step)) throw new ArgumentException($"{JobSchedule.Label(step)} is not a step of the pipeline");
            PipelineLock? running = null;
            try { running = (await _flow.QueueAsync(ct)).Lock; }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "reading the pipeline queue failed (apply the Pro database schema again)"); }
            var mode = stored.Mode is "flow" or "schedules" ? stored.Mode : JobFlow.InferMode(jobs);
            var before = JobFlow.ToJson(flow with { Mode = mode });
            message = await PipelineRequests.QueueAsync(_flow, _jobs, "from-step", step, User.ChangeName(), running, ct) + "; the steps above it do not run";
            await AuditAsync("re-run the pipeline from a step (from a data-quality warning)", before, message, ct);
            message += ".";
        }
        catch (UnauthorizedAccessException ex) { return AccessResults.Refused(Request, AccessDecision.No(ex.Message)); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or HttpRequestException)
        {
            _log.LogError(ex, "data quality: re-run from a step failed");
            message = "Re-run from here failed -- " + ex.Message;
            kind = "error";
        }
        if (Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase))
            return new JsonResult(new { ok = kind != "error", kind, message });
        TempData["toast"] = message;
        TempData["toastKind"] = kind;
        return Redirect(Link(Run, Group));
    }

    /// The same change log row Operations > Jobs writes for a pipeline action.
    private async Task AuditAsync(string what, string old, string @new, CancellationToken ct)
    {
        try
        {
            var by = User.ChangeName();
            await _sql.QueryAsync(JobsModel.AuditSql, new Dictionary<string, object?>
            {
                ["Name"] = JobFlow.FlowJob, ["Old"] = old, ["New"] = @new, ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = what,
            }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "auditing {What} failed", what); }
    }
}
