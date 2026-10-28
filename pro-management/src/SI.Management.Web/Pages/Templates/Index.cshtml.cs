using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Export;

namespace SI.Management.Web.Pages.Templates;

/// <summary>
/// Template conformance (Admin and Viewer): every configuration template of this install and what the customer did with
/// it -- UpToDate / Overridden / Disabled / UpgradeAvailable / Own / Retired -- with the per-install counts and the
/// recorded template fingerprint. Selecting an item shows WHAT changed: the template's own changes since the customer's
/// version was made, and how the customer's version differs from the current template. An Admin stages "take the new
/// template" or "keep mine and acknowledge"; nothing is written before Review &amp; commit, and the name recorded is the
/// signed-in identity.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly TemplateConformance _conformance;
    private readonly ChangeService _changes;
    private readonly TemplateReleases _releases;
    private readonly ILogger<IndexModel> _log;

    public IndexModel(TemplateConformance conformance, ChangeService changes, TemplateReleases releases, ILogger<IndexModel> log)
    { _conformance = conformance; _changes = changes; _releases = releases; _log = log; }

    /// The template pack the templates are compared with (null = none recorded yet).
    public InstalledPack? ComparedWith { get; private set; }

    [BindProperty(SupportsGet = true)] public string? Kind { get; set; }
    [BindProperty(SupportsGet = true)] public string? State { get; set; }
    [BindProperty(SupportsGet = true)] public string? Key { get; set; }

    public IReadOnlyList<ConformanceRow> Rows { get; private set; } = Array.Empty<ConformanceRow>();
    public ConformanceSummary? Summary { get; private set; }
    public ConformanceItem? Selected { get; private set; }
    public IReadOnlyList<ContentChange> TemplateChanges { get; private set; } = Array.Empty<ContentChange>();
    public IReadOnlyList<ContentChange> YourChanges { get; private set; } = Array.Empty<ContentChange>();
    public bool SchemaMissing { get; private set; }
    public string? Error { get; private set; }
    public List<QueryInfo> Queries { get; } = new();
    /// #405: every item you edited whose vendor template changed since -- "SecurityInsight's default changed: compare, keep yours
    /// or take ours" -- with the class of each (whatever the filters say).
    public IReadOnlyList<(ConformanceRow Row, string Class)> DefaultChanged { get; private set; } = Array.Empty<(ConformanceRow, string)>();
    /// #405: the install runs the split install (cfg.InstallState TemplateMode = split).
    public bool Split { get; private set; }

    /// The kinds and states the list is filtered to (owner 2026-10-19: every filter takes several values; none = all).
    public IReadOnlyList<string> Kinds { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> ChosenStates { get; private set; } = Array.Empty<string>();

    public async Task OnGetAsync(CancellationToken ct)
    {
        // the filters are closed lists: anything else is ignored rather than sent anywhere
        Kinds = MultiFilter.ValuesOf(Request.Query, "kind").Where(k => TemplateConformance.TemplatedKinds.Contains(k, StringComparer.Ordinal)).ToList();
        ChosenStates = MultiFilter.ValuesOf(Request.Query, "state").Where(s => TemplateConformance.States.Contains(s, StringComparer.Ordinal)).ToList();
        // one kind: the list of that kind and the item of it (?kind=&key=); several: every kind, then the chosen ones
        Kind = Kinds.Count == 1 ? Kinds[0] : null;
        State = ChosenStates.Count == 1 ? ChosenStates[0] : null;
        try
        {
            var (tables, versioning) = await _conformance.SchemaAsync(ct);
            if (!tables || !versioning) { SchemaMissing = true; return; }
            var all = await _conformance.ListAsync(Kind, ct);
            if (Kinds.Count > 1) all = all.Where(r => Kinds.Contains(r.Kind, StringComparer.Ordinal)).ToList();
            Queries.Add(QueryInfo.Sql(TemplateConformance.ListSql, "Template conformance"));
            Summary = await _conformance.SummaryAsync(all, ct);
            var classes = TemplateClasses.Shipped;
            DefaultChanged = all.Where(r => r.Conformance == TemplateConformance.UpgradeAvailable).Select(r => (r, classes.Of(r.Kind, r.ItemKey))).ToList();
            try
            {
                var (packTable, _) = await _releases.SchemaAsync(ct);
                var state = await _releases.InstallStateAsync(ct);
                Split = state.TryGetValue("TemplateMode", out var mode) && mode.Value?.Trim() == "split";
                ComparedWith = InstalledPack.From(state, packTable ? await _releases.StagedAsync(ct) : Array.Empty<StagedPackInfo>());
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the installed template pack could not be read"); }
            Rows = ChosenStates.Count == 0 ? all : all.Where(r => ChosenStates.Contains(r.Conformance, StringComparer.Ordinal)).ToList();
            if (!string.IsNullOrWhiteSpace(Key) && Kind is not null)
            {
                Selected = await _conformance.ItemAsync(Kind, Key, ct);
                Queries.Add(QueryInfo.Sql(TemplateConformance.ItemSql, "Items of the selected template"));
                if (Selected is { } s && s.Row.Conformance is TemplateConformance.UpgradeAvailable or TemplateConformance.Overridden)
                {
                    if (s.BaseBody is not null) TemplateChanges = TemplateConformance.Diff(s.BaseBody, s.TemplateBody, s.Format);
                    YourChanges = TemplateConformance.Diff(s.TemplateBody, s.OverrideBody, s.Format);
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the template conformance view could not be read");
            Error = "The templates could not be read from the Pro database: " + ex.Message;
        }
    }

    /// Excel workbook of the conformance list (the current kind / state filter) and the per-state counts.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        Key = null;   // the list, not one item's diff
        await OnGetAsync(ct);
        return await ExcelExport.FileAsync("templates", null, (x, info) =>
        {
            info.Filter("Kind", Kinds.Count == 0 ? null : string.Join(" or ", Kinds)).Filter("State", ChosenStates.Count == 0 ? null : string.Join(" or ", ChosenStates.Select(Label)));
            if (Error is not null) info.Notes.Add(Error);
            if (SchemaMissing) info.Notes.Add(TemplateConformance.MissingSchemaMessage);
            if (Summary is { } s)
            {
                info.Add("Conformant", s.Conformant).Add("Template fingerprint", s.Fingerprint ?? "(not recorded)")
                    .Add("Fingerprint release", s.FingerprintVersion ?? "").Add("Fingerprint recorded", s.FingerprintAt).Add("Fingerprint recorded by", s.FingerprintBy ?? "");
            }
            x.Sheet(info, "Templates", new[] { "Kind", "Item", "State", "Template version", "Your version made against", "Your version", "Changed by", "Changed", "Template content hash", "Base hash", "Retired" },
                Rows.Select(r => new object?[]
                {
                    r.Kind, r.ItemKey, Label(r.Conformance), r.TemplateVersion, r.BaseVersion, r.State, r.UpdatedBy, r.UpdatedAt, r.ContentHash, r.BaseHash, r.RetiredAt,
                }));
            x.Sheet(info, "Summary", new[] { "State", "Items" },
                TemplateConformance.States.Select(st => new object?[] { Label(st), Summary is { } s2 && s2.Counts.TryGetValue(st, out var n) ? n : 0 }));
            return Task.CompletedTask;
        }, ct);
    }

    [BindProperty] public string? Decision { get; set; }
    [BindProperty] public string? Reason { get; set; }

    /// Admin only: stage "take" or "keep" for one item. Nothing is written here.
    [SI.Management.Web.Audit.Audited("template.conformance.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        (StagedChange? change, IReadOnlyList<string> why) r = Decision switch
        {
            "take" => await _changes.NewTemplateDecisionAsync(Kind ?? "", Key ?? "", true, Reason ?? "", ct),
            "keep" => await _changes.NewTemplateDecisionAsync(Kind ?? "", Key ?? "", false, Reason ?? "", ct),
            _ => (null, new[] { $"unknown decision '{Decision}'" }),
        };
        if (r.change is not null)
        {
            await _changes.StageAsync(User, r.change, ct);
            TempData["toast"] = "Staged: " + r.change.Title + ". Nothing is written until you review and commit.";
            TempData["toastKind"] = "ok";
        }
        else
        {
            TempData["toast"] = "Not staged: " + string.Join("; ", r.why);
            TempData["toastKind"] = "error";
        }
        return RedirectToPage(new { kind = Kind, key = Key, state = State });
    }

    public static string Badge(string state) => state switch
    {
        TemplateConformance.UpToDate => "good",
        TemplateConformance.UpgradeAvailable => "warn",
        TemplateConformance.Retired => "bad",
        _ => "",
    };

    public static string Label(string state) => state switch
    {
        TemplateConformance.UpToDate => "Up to date",
        TemplateConformance.UpgradeAvailable => "Upgrade available",
        _ => state,
    };

    public static string Short(string? hash) => string.IsNullOrEmpty(hash) ? "(none)" : hash.Length > 12 ? hash[..12] : hash;
}
