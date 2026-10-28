using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// Edit one setting: the form (GET) -> Review, a diff old -> new after validation (POST ?handler=Review) -> Save
/// (POST ?handler=Save). Nothing is written before Save, and Save is refused when the row moved on since it was read
/// (the RowVersion captured when the form was opened travels with the change).
/// </summary>
public sealed class EditModel : PageModel
{
    private readonly SettingsCatalog _catalog;
    private readonly ISettingsStoreReader _reader;
    private readonly SettingsWriter _writer;

    public EditModel(SettingsCatalog catalog, ISettingsStoreReader reader, SettingsWriter writer) { _catalog = catalog; _reader = reader; _writer = writer; }

    [BindProperty(SupportsGet = true)] public string? Name { get; set; }
    [BindProperty(SupportsGet = true)] public string? Scope { get; set; }
    /// #914: a value another page proposes (the ServiceNow resync / test batch request): shown in the form, saved only through
    /// Review and Save like every value (never on the GET).
    [BindProperty(SupportsGet = true)] public string? Proposed { get; set; }
    [BindProperty] public string ChangeAction { get; set; } = "Set";
    [BindProperty] public string? ValueText { get; set; }
    [BindProperty] public string? KeyVaultSecretName { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// "scope=version;..." -- the RowVersion of every row of this setting when the form was opened.
    [BindProperty] public string? ReadVersions { get; set; }

    public CatalogSetting? Setting { get; private set; }
    public IReadOnlyList<SettingRow> Rows { get; private set; } = Array.Empty<SettingRow>();
    public IReadOnlyList<string> Scopes { get; private set; } = Array.Empty<string>();
    public DiffEntry? Diff { get; private set; }
    public long? ExpectedVersion { get; private set; }
    public string? Error { get; private set; }
    public bool Stale { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return NotFound();
        if (string.IsNullOrEmpty(Scope)) Scope = Rows.Count == 1 ? Rows[0].Scope : Setting!.DefaultScope;
        var row = Rows.FirstOrDefault(r => r.Scope == Scope);
        if (row is not null)
        {
            ValueText = SettingJson.ToFormText(row.ValueJson);
            KeyVaultSecretName = row.KeyVaultSecretName;
        }
        if (!string.IsNullOrWhiteSpace(Proposed) && Proposed.Length <= 200) ValueText = Proposed.Trim();
        ReadVersions = string.Join(";", Rows.Select(r => r.Scope + "=" + r.Version.ToString(CultureInfo.InvariantCulture)));
        return Page();
    }

    [SI.Management.Web.Audit.NotAudited("a review: shows the change before it is saved and writes nothing (the plan is not recorded -- AUDIT-1.2.6)")]
    public async Task<IActionResult> OnPostReviewAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return NotFound();
        var change = BuildChange();
        var (prepared, refusal) = _writer.Prepare(change);
        if (prepared is null) { Error = refusal; return Page(); }
        var current = Rows.FirstOrDefault(r => r.Scope == prepared.Change.Scope);
        if ((current?.Version) != change.ExpectedVersion) { Stale = true; return Page(); }
        Diff = SettingsDiff.Build(current, prepared);
        if (Diff.Kind == DiffKind.Unchanged) { Error = "Nothing changes -- the value is already this."; Diff = null; }
        return Page();
    }

    [SI.Management.Web.Audit.Audited("settings.value.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        // the licence settings are the install's lifecycle: SuperAdmin (#253)
        if (AccessLifecycle.IsLicenceSetting(Name) && !User.IsSuperAdmin()) return AccessResults.Refused(Request, AccessDecision.No("the licence settings need SuperAdmin"));
        if (!await LoadAsync(ct)) return NotFound();
        var change = BuildChange();
        var result = await _writer.WriteAsync(change, User.ChangeName(), ct);
        switch (result.Status)
        {
            case WriteStatus.Saved:
                return RedirectToPage("Index", new { saved = result.Message, q = change.Name });
            case WriteStatus.Stale:
                Stale = true;
                return Page();
            default:
                Error = result.Message;
                return Page();
        }
    }

    /// The CMDB source is switched on its own page, which explains what the switch does before anything is saved.
    public override void OnPageHandlerExecuting(Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutingContext context)
    {
        if (string.Equals(Name, SI.Management.Web.Cmdb.CmdbSources.Setting, StringComparison.OrdinalIgnoreCase)) context.Result = RedirectToPage("/Cmdb/Source");
    }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        Setting = string.IsNullOrWhiteSpace(Name) ? null : _catalog.Find(Name);
        if (Setting is null) return false;
        Name = Setting.Name;
        var (rows, _) = await _reader.ReadSettingsAsync(ct);
        Rows = rows.Where(r => r.Name.Equals(Setting.Name, StringComparison.OrdinalIgnoreCase)).ToList();
        Scopes = Setting.AllowedScopes().Concat(Rows.Select(r => r.Scope)).Distinct(StringComparer.Ordinal).ToList();
        return true;
    }

    private SettingWrite BuildChange()
    {
        var scope = Scope ?? Setting!.DefaultScope;
        ExpectedVersion = ParseVersions(ReadVersions).TryGetValue(scope, out var v) ? v : null;
        var isSet = ChangeAction == "Set";
        return new SettingWrite(Setting!.Name, scope, ChangeAction,
            // a secret has no value field; one posted anyway is passed on so the writer refuses it, never dropped silently
            isSet && (!Setting.Secret || !string.IsNullOrEmpty(ValueText)) ? SettingJson.FromForm(Setting, ValueText) : null,
            isSet && Setting.Secret ? KeyVaultSecretName : null,
            ExpectedVersion, Reason);
    }

    internal static Dictionary<string, long> ParseVersions(string? s)
    {
        var d = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var part in (s ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var i = part.LastIndexOf('=');
            if (i > 0 && long.TryParse(part[(i + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)) d[part[..i]] = v;
        }
        return d;
    }
}
