using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Columns;
using SI.Management.Web.GetStarted;
using SI.Management.Web.Jobs;
using SI.Management.Web.NewContext;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.SchemaOverlay;

/// A read permission a source would need: what it is needed for, whether it is one of SecurityInsight's own permission
/// set (then <see cref="Fix"/> holds who runs the grant, where, and the filled-in commands) or not (then it is only named).
public sealed record PermissionProposal(string Permission, string For, bool InPermissionSet, PermissionFixBlock? Fix);

/// <summary>
/// Configuration > New context available (continuous discovery): what every source offers that was not there before --
/// per source the property, when it was first seen, a sample value, how many records carry it, and whether an SI field
/// already reads it or a view already opens with it. Readers see it. An Admin can, in one step each, add the column to a
/// view's default layout (for everyone without a layout of their own) or map the property to an SI field -- the mapping is
/// STAGED and written only at Review &amp; commit. A read permission a source would need is proposed with the filled-in
/// command; nothing on this page requests or grants one. The page reads prepared rows only (sidata.SourceProperty,
/// sidata.SourceDiscoveryState).
/// </summary>
public sealed class NewContextModel : PageModel
{
    private readonly INewContextStore _store;
    private readonly IColumnPromotions _promotions;
    private readonly RiskFactorStore _model;
    private readonly ChangeService _changes;
    private readonly ISettingsStoreReader _settings;
    private readonly IOptions<JobsOptions> _jobs;
    private readonly ILogger<NewContextModel> _log;

    public NewContextModel(INewContextStore store, IColumnPromotions promotions, RiskFactorStore model, ChangeService changes, ISettingsStoreReader settings,
        IOptions<JobsOptions> jobs, ILogger<NewContextModel> log)
    { _store = store; _promotions = promotions; _model = model; _changes = changes; _settings = settings; _jobs = jobs; _log = log; }

    public const string ShowWeek = "week";
    public const string ShowMonth = "month";
    public const string ShowNew = "new";
    public const string ShowKnown = "known";
    public static readonly IReadOnlyList<(string Key, string Label)> Windows =
        [(ShowWeek, "This week"), (ShowMonth, "Last 30 days"), (ShowNew, "Everything new"), (ShowKnown, "Everything known")];

    /// week (the default) | month | new (everything first seen after discovery started) | known (also what was there at the start)
    [BindProperty(SupportsGet = true)] public string? Show { get; set; }
    [BindProperty] public string? Id { get; set; }
    [BindProperty] public string? Target { get; set; }
    [BindProperty] public string? Field { get; set; }
    [BindProperty] public string? Column { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public NewContextView View { get; private set; } = NewContextView.Missing;
    public string? Error { get; private set; }
    /// The promoted columns per target ("" = every view).
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Promoted { get; private set; } = new Dictionary<string, IReadOnlyList<string>>();
    public IReadOnlyList<PermissionProposal> Proposals { get; private set; } = Array.Empty<PermissionProposal>();
    public IReadOnlyList<string> SiFields { get; private set; } = Array.Empty<string>();

    public string Window => Windows.Any(w => w.Key == Show) ? Show! : ShowWeek;

    /// The sources in the order the page lists them: the ones every install has, then any other the data names.
    public IReadOnlyList<string> SourcesShown =>
        NewContextText.Sources.Concat(View.Counts.Select(c => c.Source)).Concat(View.States.Select(s => s.Source)).Concat(View.Properties.Select(p => p.Source))
            .Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// Where a property already shows: the SI fields that read it, and the views that open with it.
    public string Used(SourcePropertyRow r)
    {
        var parts = new List<string>();
        if (r.Mapped.Count > 0) parts.Add("read by " + string.Join(", ", r.Mapped));
        var keys = r.Mapped.Select(DataColumnKeys.Field).ToList();
        if (r.ColumnKey is { } own) keys.Add(own);
        var views = Promoted.Where(kv => kv.Value.Any(k => keys.Contains(k, StringComparer.OrdinalIgnoreCase))).Select(kv => NewContextText.TargetLabel(kv.Key)).ToList();
        if (r.Mapped.Any(f => DataViewDefaults.CiContext.Contains(DataColumnKeys.Field(f), StringComparer.OrdinalIgnoreCase))) views.Insert(0, "the standard layout of the views of CIs");
        if (views.Count > 0) parts.Add("opens with: " + string.Join(", ", views.Distinct(StringComparer.Ordinal)));
        return parts.Count == 0 ? "not used yet" : string.Join("; ", parts);
    }

    private static int Days(string window) => window switch { ShowMonth => 30, ShowNew or ShowKnown => 0, _ => 7 };

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    private async Task LoadAsync(CancellationToken ct)
    {
        try { View = await _store.ReadAsync(Days(Window), Window == ShowKnown, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "new context: the discovery tables could not be read");
            Error = "The list of what each source offers could not be read: " + ex.Message;
            return;
        }
        var promoted = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (target, _) in NewContextText.Targets)
        {
            try { promoted[target] = await _promotions.ReadAsync(target, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "new context: the promoted columns could not be read"); }
        }
        Promoted = promoted;
        if (User.IsAdmin()) SiFields = NewContextText.SiFields();
        Proposals = await ProposalsAsync(ct);
    }

    /// The read permissions a source would need: a read the engine saw refused, and a property known to need its own.
    private async Task<IReadOnlyList<PermissionProposal>> ProposalsAsync(CancellationToken ct)
    {
        var needs = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string? permission, string what)
        {
            if (string.IsNullOrWhiteSpace(permission)) return;
            if (!needs.TryGetValue(permission.Trim(), out var list)) needs[permission.Trim()] = list = new List<string>();
            if (!list.Contains(what, StringComparer.Ordinal)) list.Add(what);
        }
        foreach (var s in View.States.Where(s => !string.IsNullOrWhiteSpace(s.NeedsPermission)))
            Add(s.NeedsPermission, NewContextText.Source(s.Source) + ": " + s.RecordType.Replace('_', ' ') + " could not be read");
        foreach (var p in View.Properties.Where(p => !p.Collected && !string.IsNullOrWhiteSpace(p.NeedsPermission)))
            Add(p.NeedsPermission, NewContextText.Source(p.Source) + ": " + p.MappingPath);
        if (needs.Count == 0) return Array.Empty<PermissionProposal>();

        PermissionFixInstall? install = null;
        try { install = GetStartedPermissionFix.Resolve((await _settings.ReadSettingsAsync(ct)).Rows, _jobs.Value); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "new context: the install's names could not be read; the grant command is shown without them"); }

        var list = new List<PermissionProposal>();
        foreach (var (permission, what) in needs.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            var inSet = NewContextText.Grantable.Contains(permission);
            PermissionFixBlock? fix = null;
            if (inSet && install is not null)
            {
                var area = permission.Equals("Reader", StringComparison.OrdinalIgnoreCase) ? "Azure" : "Microsoft Graph";
                fix = GetStartedPermissionFix.Build(new[] { new PermissionGap(area, permission, "missing", GetStartedPermissionFix.GrantScript) }, null, null, install);
            }
            list.Add(new PermissionProposal(permission, string.Join("; ", what.Take(6)) + (what.Count > 6 ? "; ..." : ""), inSet, fix));
        }
        return list;
    }

    private IActionResult Toast(bool ok, string text)
    {
        TempData["toast"] = text;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage(new { show = Window });
    }

    /// Admin only: the property's column joins the default layout of the chosen view(s) -- the SI field that reads it when
    /// one is named (a typed column every view has), else the source's own column.
    [SI.Management.Web.Audit.Audited("view.columns.save")]
    public async Task<IActionResult> OnPostPromoteAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var target = Target ?? "";
        if (!NewContextText.Targets.Any(t => t.Target == target)) return Toast(false, "Not added: choose the view the column is added to.");
        var row = await _store.FindAsync(Id ?? "", ct);
        if (row is null) return Toast(false, "Not added: the property is not in the list any more.");
        if (!row.Collected) return Toast(false, "Not added: SecurityInsight does not read this property yet -- the column would stay empty.");
        var key = Field is { Length: > 0 } f && row.Mapped.Contains(f, StringComparer.Ordinal) ? DataColumnKeys.Field(f) : row.ColumnKey;
        if (key is null || !DataColumnKeys.IsValid(key))
            return Toast(false, "Not added: this property is not a column of the data views by itself. Map it to an SI field first -- the field is then a column of every view.");
        var have = await _promotions.ReadAsync(target, ct);
        if (have.Contains(key, StringComparer.OrdinalIgnoreCase)) return Toast(true, DataColumnKeys.Label(key) + " is already in that default layout.");
        var saved = await _promotions.SaveAsync(target, have.Append(key).ToList(), User.ChangeName(), ct);
        return saved
            ? Toast(true, $"Added: {DataColumnKeys.Label(key)} now opens with \"{NewContextText.TargetLabel(target)}\" for everyone without a layout of their own.")
            : Toast(false, "Not added: the column layouts are not in the Pro database yet (the next settings update adds them).");
    }

    /// Admin only: a promoted column leaves the default layout of the target again.
    [SI.Management.Web.Audit.Audited("view.columns.save")]
    public async Task<IActionResult> OnPostUnpromoteAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var target = Target ?? "";
        if (!NewContextText.Targets.Any(t => t.Target == target) || string.IsNullOrWhiteSpace(Column)) return Toast(false, "Not removed: the column or its view is not known.");
        var have = await _promotions.ReadAsync(target, ct);
        var left = have.Where(k => !k.Equals(Column, StringComparison.OrdinalIgnoreCase)).ToList();
        if (left.Count == have.Count) return Toast(true, "That column was not in the default layout.");
        var saved = await _promotions.SaveAsync(target, left, User.ChangeName(), ct);
        return saved ? Toast(true, $"Removed: {DataColumnKeys.Label(Column!)} no longer opens with \"{NewContextText.TargetLabel(target)}\".")
            : Toast(false, "Not removed: the column layouts are not in the Pro database yet.");
    }

    /// Admin only: STAGES the mapping that makes an SI field read the property. Nothing is written until Review &amp; commit.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostMapAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var row = await _store.FindAsync(Id ?? "", ct);
        if (row is null) return Toast(false, "Not staged: the property is not in the list any more.");
        var rows = await _model.ListAsync(ct);
        if (rows is null) return Toast(false, "Not staged: " + RiskFactorStore.MissingSchemaMessage);
        var (key, body, why) = NewContextText.Mapping(rows, row, Field?.Trim());
        if (key is null) return Toast(false, "Not staged: " + string.Join("; ", why) + ".");
        var reason = string.IsNullOrWhiteSpace(Reason) ? $"New context available: {NewContextText.Source(row.Source)} {row.MappingPath}" : Reason.Trim();
        var (change, problems) = await _changes.NewDataModelItemAsync(key, ItemOverrideRepository.StateOverride, body, reason, ct);
        if (change is null) return Toast(false, "Not staged: " + string.Join("; ", problems) + ".");
        await _changes.StageAsync(User, change, ct);
        return Toast(true, $"Staged: {Field?.Trim()} reads {row.MappingPath}. Nothing is written until you review and commit; the next run of that source then fills the field.");
    }
}
