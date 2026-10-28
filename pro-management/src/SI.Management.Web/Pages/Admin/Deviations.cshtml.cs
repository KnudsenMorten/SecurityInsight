using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Deviations;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Every deviation from the shipped defaults in one place: exemptions, Risk Analysis exclusions, disabled detections,
/// tier moves, item overrides, risk weights and settings that differ from their shipped default -- who, when, why and
/// until when. Read-only. Filters by kind / owner / age / expiry; each row links to its change history; CSV export (and
/// Excel, when a workbook writer is registered -- see <see cref="IDeviationWorkbookWriter"/>). Admin only, like Settings
/// (the /Admin folder's policy).
/// </summary>
public sealed class DeviationsModel : PageModel
{
    private readonly IDeviationSource _source;
    private readonly SettingsCatalog _catalog;
    private readonly TimeProvider _clock;
    private readonly IDeviationWorkbookWriter? _xlsx;
    private readonly ILogger<DeviationsModel> _log;

    public DeviationsModel(IDeviationSource source, SettingsCatalog catalog, TimeProvider clock, IServiceProvider services, ILogger<DeviationsModel> log)
    {
        _source = source; _catalog = catalog; _clock = clock; _log = log;
        _xlsx = services.GetService<IDeviationWorkbookWriter>();
        _flow = services.GetService<SI.Management.Web.Exemptions.ExemptionWorkflow>();
    }

    private readonly SI.Management.Web.Exemptions.ExemptionWorkflow? _flow;

    /// #252: the exemptions no owner has reviewed in time ("exemption/&lt;id&gt;" history names). Flagged here, beside
    /// the report's own status; reading them never fails the page.
    public IReadOnlySet<string> ReviewOverdue { get; private set; } = new HashSet<string>();

    private async Task LoadReviewFlagsAsync(CancellationToken ct)
    {
        if (_flow is null) return;
        try
        {
            if (!await _flow.ReadyAsync(ct)) return;
            var s = await _flow.SettingsAsync(ct);
            var now = _clock.GetUtcNow().UtcDateTime;
            ReviewOverdue = (await _flow.ExemptionsAsync(ct)).Where(e => e.IsReviewOverdue(now, s.ReviewOverdueDays))
                .Select(e => "exemption/" + e.ExemptionId.ToString(CultureInfo.InvariantCulture)).ToHashSet(StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the exemption review state could not be read"); }
    }

    [BindProperty(SupportsGet = true)] public string? Kind { get; set; }
    [BindProperty(SupportsGet = true)] public string? Owner { get; set; }
    [BindProperty(SupportsGet = true)] public string? Age { get; set; }
    [BindProperty(SupportsGet = true)] public string? Expiry { get; set; }

    public IReadOnlyList<DeviationRow> All { get; private set; } = Array.Empty<DeviationRow>();
    public IReadOnlyList<DeviationRow> Rows { get; private set; } = Array.Empty<DeviationRow>();
    public IReadOnlyList<string> Queries { get; private set; } = SqlDeviationSource.All;
    public string? Error { get; private set; }
    public bool ExcelAvailable => _xlsx is not null;
    public int Expiring => All.Count(r => r.Status == "expiring");
    public int Expired => All.Count(r => r.Status == "expired");

    public DeviationFilter Filter => new DeviationFilter(Kind, Owner, Age, Expiry).Normalize();

    /// One choice of a filter dropdown: its value, its plain label and how many deviations it gives under the OTHER filters.
    public sealed record Choice(string Value, string Label, int Count);

    private int CountWith(DeviationFilter f) => f.Apply(All, _clock.GetUtcNow().UtcDateTime).Count();

    /// #287: the choices with their counts (computed under the other filters, so a count is what picking it gives), the
    /// ones with items first in their usual order, the empty ones after.
    private static IReadOnlyList<Choice> Ordered(IEnumerable<Choice> c) { var l = c.ToList(); return l.Where(x => x.Count > 0).Concat(l.Where(x => x.Count == 0)).ToList(); }
    public IReadOnlyList<Choice> KindChoices => Ordered(DeviationReport.Kinds.Select(k => new Choice(k, DeviationReport.KindLabel(k), CountWith(Filter with { Kind = k }))));
    public IReadOnlyList<Choice> AgeChoices => Ordered(DeviationFilter.Ages.Select(a => new Choice(a, AgeLabel(a), CountWith(Filter with { Age = a }))));
    public IReadOnlyList<Choice> ExpiryChoices => Ordered(DeviationFilter.Expiries.Select(e => new Choice(e, ExpiryLabel(e), CountWith(Filter with { Expiry = e }))));
    /// "All kinds (163)" / "Any age (...)" / "Any (...)": the total under the other filters.
    public int AnyKind => CountWith(Filter with { Kind = null });
    public int AnyAge => CountWith(Filter with { Age = null });
    public int AnyExpiry => CountWith(Filter with { Expiry = null });

    public static string AgeLabel(string a) => a switch
    {
        "7" => "changed in the last 7 days", "30" => "changed in the last 30 days", "90" => "changed in the last 90 days",
        "older90" => "unchanged for over 90 days", "older365" => "unchanged for over a year", _ => a,
    };

    public static string ExpiryLabel(string e) => e switch
    {
        "expiring" => "expiring within 30 days", "has-expiry" => "has an expiry", "no-expiry" => "no expiry", _ => e,
    };

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        try
        {
            var (inputs, queries) = await _source.ReadAsync(ct);
            Queries = queries;
            All = DeviationReport.Build(inputs, _catalog.All, _clock.GetUtcNow().UtcDateTime);
            Rows = Filter.Apply(All, _clock.GetUtcNow().UtcDateTime).ToList();
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the deviation report failed");
            Error = "The deviation report could not be read from the Pro database: " + ex.Message;
            return false;
        }
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (await LoadAsync(ct)) await LoadReviewFlagsAsync(ct);
    }

    private string FileName(string ext) => "securityinsight-deviations-" + _clock.GetUtcNow().UtcDateTime.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "." + ext;

    /// The current filtered view as CSV (UTF-8 with a BOM, so a spreadsheet reads it right; formula-looking cells defused).
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return StatusCode(StatusCodes.Status503ServiceUnavailable, Error ?? "");
        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(DeviationReport.ToCsv(Rows))).ToArray();
        return File(bytes, "text/csv; charset=utf-8", FileName("csv"));
    }

    /// The current filtered view as an Excel workbook -- only when a workbook writer is registered (404 otherwise).
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        if (_xlsx is null) return NotFound("Excel export is not available in this version -- use CSV.");
        if (!await LoadAsync(ct)) return StatusCode(StatusCodes.Status503ServiceUnavailable, Error ?? "");
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit) audit.Rows = Rows.Count;   // #260: what left the app
        return File(_xlsx.Write(Rows, "Deviations"), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", FileName("xlsx"));
    }
}
