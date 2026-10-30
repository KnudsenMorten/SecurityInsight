using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// Every setting, laid out the way PIM Manager's settings page does it: a category bar (one category at a time,
/// remembered per browser), one card per topic with one Save, and in each card a field per setting with the editor its
/// type calls for -- a switch, a number with its limits, a dropdown, a text box, address chips for a mail list, a Key
/// Vault secret NAME for a secret. A setting without a database row shows its default. A card's Save writes only the
/// fields that changed, each through the settings writer (validation, the version check, the change log).
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly SettingsCatalog _catalog;
    private readonly ISettingsStoreReader _reader;
    private readonly SettingsWriter _writer;
    private readonly ILogger<IndexModel> _log;
    private readonly LicenceRequestReader _licence;
    private readonly UpdateStateReader _updates;
    private readonly InstalledLicenceReader _installed;
    private readonly InstallKeyClaimAgain _claimAgain;
    private readonly SettingsSaver _saver;
    private readonly IDetailedWorkbookSize _workbookSize;

    public IndexModel(SettingsCatalog catalog, ISettingsStoreReader reader, SettingsWriter writer, LicenceRequestReader licence, UpdateStateReader updates,
        InstalledLicenceReader installed, InstallKeyClaimAgain claimAgain, SettingsSaver saver, IDetailedWorkbookSize workbookSize, ILogger<IndexModel> log)
    { _catalog = catalog; _reader = reader; _writer = writer; _licence = licence; _updates = updates; _installed = installed; _claimAgain = claimAgain; _saver = saver; _workbookSize = workbookSize; _log = log; }

    /// The rows of the newest complete detailed collection (null = not known): above DetailedWorkbookLimit.RowLimit the
    /// detailed Excel switch is greyed out.
    public long? DetailedRows { get; private set; }

    /// The line a setting's switch is greyed out with (only SI_RA_ExcelExport_Detailed, above the size a workbook holds); null = usable.
    public string? Unavailable(string name) =>
        string.Equals(name, DetailedWorkbookLimit.Setting, StringComparison.OrdinalIgnoreCase) ? DetailedWorkbookLimit.Unavailable(DetailedRows) : null;

    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true)] public bool OnlySet { get; set; }
    /// Show every category's advanced settings (the no-script form of the per-category "Show advanced").
    [BindProperty(SupportsGet = true)] public bool Advanced { get; set; }
    [BindProperty(SupportsGet = true)] public string? Saved { get; set; }
    /// The category to open (a deep link from another page: ?cat=mail-notifications&amp;card=...).
    [BindProperty(SupportsGet = true)] public string? Cat { get; set; }

    /// The category the licence and update state are shown in.
    public const string LicenceCategory = "Licence & updates";

    public IReadOnlyList<SettingsCategory> Categories { get; private set; } = Array.Empty<SettingsCategory>();
    public bool Filtered => !string.IsNullOrWhiteSpace(Q) || OnlySet;
    public string? Query { get; private set; }
    public string? Error { get; private set; }
    public int Total => _catalog.All.Count;
    public int Shown { get; private set; }
    public int InDatabase { get; private set; }
    /// Whether this person may change the SuperAdmin-only settings (the licence settings).
    public bool CanSuperAdmin { get; private set; }
    /// The installed licence as the updater last verified it; null = not recorded yet.
    public InstalledLicence? Installed { get; private set; }
    public string? InstalledError { get; private set; }
    /// Today (UTC) -- the day the licence state is worked out for.
    public DateTime TodayUtc { get; private set; } = DateTime.UtcNow;
    public LicenceRequestState? Licence { get; private set; }
    public string? LicenceError { get; private set; }
    public UpdateState? Updates { get; private set; }
    public string? UpdatesError { get; private set; }
    /// The install key in plain words (held / requested / refused again / claimed); null = nothing to say.
    public InstallKeyStatus? InstallKey { get; private set; }
    /// The id of the Licence &amp; updates category (the claim-again form returns there).
    public string? LicenceCategoryId => Categories.FirstOrDefault(c => c.Name == LicenceCategory)?.Id;
    public bool LicenceAutoOn { get; private set; } = true;
    public bool InvardiaUpdatesOn { get; private set; } = true;

    public async Task OnGetAsync(CancellationToken ct)
    {
        CanSuperAdmin = User.IsSuperAdmin();
        IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
        try
        {
            (rows, Query) = await _reader.ReadSettingsAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading cfg.Setting failed");
            Error = "The settings database could not be read: " + ex.Message;
            Query = SqlSettingsReader.SettingsSql;
        }
        try { Installed = await _installed.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "reading the installed licence failed"); InstalledError = ex.Message; }
        try { Licence = await _licence.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "reading the licence request state failed"); LicenceError = ex.Message; }
        try { Updates = await _updates.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "reading the update state failed"); UpdatesError = ex.Message; }
        ClaimAgainRequest? pending = null;
        try { pending = await _claimAgain.PendingAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "reading the claim-again request failed"); }
        InstallKey = InstallKeyClaimAgain.Describe(Updates, pending);
        try { DetailedRows = await _workbookSize.ReadRowsAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "reading the detailed results' size failed"); DetailedRows = null; }
        InDatabase = rows.Count;
        LicenceAutoOn = ProAutoSwitches.IsOn(rows, ProAutoSwitches.LicenceRequest);
        InvardiaUpdatesOn = ProAutoSwitches.IsOn(rows, ProAutoSwitches.InvardiaUpdates);
        // the mail switch of a check that never mails is not shown (GuardSwitches.HiddenOnSettingsPage)
        IEnumerable<CatalogSetting> list = _catalog.All.Where(s => !SI.Management.Web.Guards.GuardSwitches.HiddenOnSettingsPage(s.Name));
        if (!string.IsNullOrWhiteSpace(Q))
        {
            var q = Q.Trim();
            list = list.Where(s => s.Matches(q));
        }
        if (OnlySet)
        {
            var set = rows.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            list = list.Where(s => set.Contains(s.Name));
        }
        var shown = list.ToList();
        Shown = shown.Count;
        Categories = SettingsLayout.Build(_catalog, shown, rows);
    }

    /// The category open when the page loads without script: the one asked for, else the first.
    public string OpenCategory =>
        Categories.FirstOrDefault(c => string.Equals(c.Id, Cat, StringComparison.OrdinalIgnoreCase))?.Id ?? Categories.FirstOrDefault()?.Id ?? "";

    /// <summary>
    /// One card's Save. The form carries, per field, v:Name (the value; a switch posts "false" then "true" when ticked),
    /// ver:Name (the RowVersion read), scope:Name and reset:Name. A field whose input was disabled (the person may not
    /// change it) posts nothing and is left alone. Every field is planned and validated first; if any is refused,
    /// nothing is written. Answers JSON to the page's script, else returns to the page with a notice.
    /// </summary>
    [Audited("settings.value.save")]
    public async Task<IActionResult> OnPostSaveCardAsync(CancellationToken ct)
    {
        var form = Request.Form;
        var card = form["card"].ToString();
        var names = form["names"].ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        // the ONE save (#446): the same code path a Get Started step uses
        var r = await _saver.SaveAsync(form, names, User, "/Admin/Settings?handler=SaveCard|card=" + card, ct);
        return Answer(r.Ok, r.Message, r.Errors, r.Fields, card);
    }

    /// <summary>
    /// "Invardia reset this install's key -- claim it again" (Settings &gt; Updates, Admin). Offered only while the install
    /// key claim is HELD (Invardia answered 409). Writes the one-shot request the updater job takes away before it claims
    /// once -- claimed, or held again on another 409; never a loop. Audited.
    /// </summary>
    [Audited("update.installkey.claim-again")]
    public async Task<IActionResult> OnPostClaimAgainAsync(CancellationToken ct)
    {
        var audit = AuditScope.Current;
        if (audit is not null) { audit.Target = "/Admin/Settings?handler=ClaimAgain|install-key"; audit.Reason = "Invardia reset this install's key -- claim it again"; }
        string message; var ok = false;
        try
        {
            var state = await _updates.ReadAsync(ct);
            var pending = await _claimAgain.PendingAsync(ct);
            var now = InstallKeyClaimAgain.Describe(state, pending);
            if (pending is not null) { message = "A claim-again request is waiting already -- the updater job claims the key once on its next run."; audit?.Set(AuditOutcomes.Refused, message); }
            else if (now is null || !now.CanClaimAgain) { message = "Nothing was requested: the install key claim is not held, so there is nothing to claim again."; audit?.Set(AuditOutcomes.Refused, message); }
            else
            {
                await _claimAgain.RequestAsync(User.ChangeName(), ct);
                if (audit is not null) { audit.BeforeJson = JsonSerializer.Serialize(new { claim = state?.Claim, claimAgain = state?.ClaimAgain }); audit.AfterJson = JsonSerializer.Serialize(new { request = "requested" }); }
                message = "Requested: the updater job claims this install's key once on its next run (every night, or start the job now). This page shows the outcome.";
                ok = true;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the claim-again request failed");
            message = "The request could not be saved: " + ex.Message;
            audit?.Set(AuditOutcomes.Error, message);
        }
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        var cat = Request.HasFormContentType ? Request.Form["cat"].ToString() : "";
        return Redirect(Url.Page("Index", new { cat = string.IsNullOrEmpty(cat) ? null : cat })! + "#updates");
    }

    private IActionResult Answer(bool ok, string message, IReadOnlyDictionary<string, string> errors, IReadOnlyDictionary<string, object>? fields, string card)
    {
        var wantsJson = Request.Headers.Accept.Any(a => a is not null && a.Contains("application/json", StringComparison.OrdinalIgnoreCase));
        if (wantsJson) return new JsonResult(new { ok, message, errors, fields = fields ?? new Dictionary<string, object>() });
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        var cat = Request.Form["cat"].ToString();
        return Redirect(Url.Page("Index", new { cat = string.IsNullOrEmpty(cat) ? null : cat })! + (string.IsNullOrEmpty(card) ? "" : "#card-" + card));
    }
}
