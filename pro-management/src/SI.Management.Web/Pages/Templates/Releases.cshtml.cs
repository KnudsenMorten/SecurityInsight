using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Pages.Templates;

/// <summary>
/// Template releases (Admin; Viewer read-only): the template pack installed on this install and the packs available to
/// it -- the newest its update ring approves, staged by the updater, or the templates shipped with the installed code --
/// compared with the templates in force BY DETECTION METHOD (engine -> method -> rules: new / changed / retired, and the
/// customer's overrides affected). An Admin stages a release of every method or of the selected ones, or a roll back of
/// selected methods to a previous version; Review &amp; commit starts the caj-si-templates job with the exact selection
/// fingerprint accepted, and the job records the release only after it wrote and verified it. History: every request
/// and every verified release.
/// </summary>
public sealed class ReleasesModel : PageModel
{
    private readonly TemplateReleases _releases;
    private readonly ChangeService _changes;
    private readonly ILogger<ReleasesModel> _log;

    public ReleasesModel(TemplateReleases releases, ChangeService changes, ILogger<ReleasesModel> log) { _releases = releases; _changes = changes; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Pack { get; set; }
    [BindProperty(SupportsGet = true)] public string? Method { get; set; }
    [BindProperty(SupportsGet = true)] public string? Item { get; set; }
    [BindProperty(SupportsGet = true)] public string? Rollback { get; set; }

    public bool SchemaMissing { get; private set; }
    public bool PackTableMissing { get; private set; }
    public string? Error { get; private set; }
    public string? PackError { get; private set; }
    public string? JobError { get; private set; }
    /// The release job is not (yet) one of this installation's jobs -- setup / the next update adds it.
    public bool JobMissing { get; private set; }
    /// What is installed, in the page's words (null = no pack recorded).
    public InstalledPack? InstalledPack { get; private set; }
    public IReadOnlyDictionary<string, InstallStateRow> Installed { get; private set; } = new Dictionary<string, InstallStateRow>();
    public IReadOnlyList<StagedPackInfo> Staged { get; private set; } = Array.Empty<StagedPackInfo>();
    public TemplatePack? Selected { get; private set; }
    public StagedPackInfo? SelectedInfo { get; private set; }
    public ReleaseDiff? Diff { get; private set; }
    public IReadOnlyList<ReleaseDiffItem> Expanded { get; private set; } = Array.Empty<ReleaseDiffItem>();
    public ReleaseDiffItem? ItemDiffOf { get; private set; }
    public IReadOnlyList<ContentChange> ItemChanges { get; private set; } = Array.Empty<ContentChange>();
    public IReadOnlyList<JobExecution> Executions { get; private set; } = Array.Empty<JobExecution>();
    public IReadOnlyList<ReleaseHistoryRow> History { get; private set; } = Array.Empty<ReleaseHistoryRow>();
    public IReadOnlyList<string> RollbackVersions { get; private set; } = Array.Empty<string>();
    public ReleaseDiff? RollbackDiff { get; private set; }
    public List<QueryInfo> Queries { get; } = new();
    public string JobName => _releases.JobName;
    public bool JobsConfigured => _releases.JobsConfigured;
    /// #405: what is installed per class (fixes with the code, Microsoft content, ring 1 direct) and the hold setting.
    public TemplateInstallSummary? Summary { get; private set; }
    /// #405: the split install is on -- packs are installed automatically; the page shows no import / release in normal use.
    public bool Split => Summary?.Split == true;
    /// #405: per staged pack, where it stands (installed / automatic / held / waiting / by hand).
    public IReadOnlyDictionary<string, TemplatePackState> PackStates { get; private set; } = new Dictionary<string, TemplatePackState>();
    /// #405: the Microsoft content a one-click roll back goes to (null = nothing earlier is kept).
    public string? PreviousMicrosoft { get; private set; }
    public TemplatePackState? SelectedState => Pack is not null && PackStates.TryGetValue(Pack, out var s) ? s : null;

    public async Task OnGetAsync(CancellationToken ct)
    {
        // closed formats: anything else is ignored rather than sent anywhere
        if (!TemplateReleases.IsPackVersion(Pack)) Pack = null;
        if (!TemplateReleases.IsPackVersion(Rollback)) Rollback = null;
        if (!TemplateReleases.IsMethodId(Method)) Method = null;
        if (Item is not null && (Item.Length > 170 || !TemplateConformance.TemplatedKinds.Any(k => Item.StartsWith(k + "/", StringComparison.Ordinal)))) Item = null;
        try
        {
            var (packTable, versioning) = await _releases.SchemaAsync(ct);
            if (!versioning) { SchemaMissing = true; return; }
            PackTableMissing = !packTable;
            Installed = await _releases.InstallStateAsync(ct);
            History = await _releases.HistoryAsync(ct);
            Queries.Add(QueryInfo.Sql(TemplateReleases.InstallSql, "Installed template packs"));
            Queries.Add(QueryInfo.Sql(TemplateReleases.HistorySql, "Release history"));
            Summary = TemplateInstallSummary.From(Installed, History, await _releases.HoldAsync(ct));
            if (packTable)
            {
                Staged = await _releases.StagedAsync(ct);
                // ring 1: the pack the direct deploy put in force reads installed (owner decision 2026-10-11)
                Summary = Summary.WithStaged(Staged);
                Queries.Add(QueryInfo.Sql(TemplateReleases.StagedListSql, "Staged releases"));
                PackStates = Staged.ToDictionary(s => s.PackVersion, s => TemplatePackState.Of(s, Summary), StringComparer.Ordinal);
                // #405: in split mode the page opens on a pack that waits for something (held, waiting, by hand) -- an
                // installed or automatic one is opened only when asked for
                var pick = Pack ?? (Split ? Staged.FirstOrDefault(s => PackStates[s.PackVersion].State is TemplatePackState.Held or TemplatePackState.Waiting)?.PackVersion
                                          : Staged.FirstOrDefault()?.PackVersion);
                SelectedInfo = Staged.FirstOrDefault(s => s.PackVersion == pick);
                if (SelectedInfo is not null)
                {
                    try
                    {
                        var (d, p) = await _releases.DiffAsync("release", SelectedInfo.PackVersion, ct);
                        Diff = d; Selected = p; Pack = SelectedInfo.PackVersion;
                        Queries.Add(QueryInfo.Sql(TemplateReleases.TemplatesSql, "What the release changes"));
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or JsonException) { PackError = ex.Message; }
                }
            }
            var (versions, _) = await _releases.RevisionsAsync(ct);
            RollbackVersions = versions;
            PreviousMicrosoft = TemplateReleases.PreviousMicrosoftVersion(versions, Summary.MicrosoftPack);
            if (Rollback is not null) RollbackDiff = (await _releases.DiffAsync("rollback", Rollback, ct)).Diff;
            var focus = RollbackDiff ?? Diff;
            if (focus is not null && Method is not null) Expanded = focus.Items.Where(i => i.MethodId == Method).ToList();
            if (focus is not null && Item is not null && focus.Items.FirstOrDefault(i => i.Name == Item) is { } it)
            {
                ItemDiffOf = it;
                ItemChanges = TemplateConformance.Diff(it.OldBody, it.NewBody, it.Format);
            }
            InstalledPack = InstalledPack.From(Installed, Staged);
            try
            {
                if (await _releases.JobInstalledAsync(ct) == false) { JobMissing = true; return; }
                Executions = await _releases.ExecutionsAsync(ct);
                if (Executions.Any(e => e.Status is "Running" or "Processing")) ViewData["RefreshSeconds"] = 15;   // the page polls while the job runs
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or HttpRequestException) { JobError = ex.Message; }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the template releases could not be read");
            Error = "The template releases could not be read from the Pro database: " + ex.Message;
        }
    }

    [BindProperty] public List<string> Methods { get; set; } = new();
    [BindProperty] public string? Scope { get; set; }
    [BindProperty] public string? Reason { get; set; }

    /// Admin only: stage a release of the selected pack (every method, or the selected ones). Nothing is written here.
    [SI.Management.Web.Audit.Audited("template.release.stage")]
    public Task<IActionResult> OnPostReleaseAsync(CancellationToken ct) => StageAsync("release", Pack, ct);

    /// Admin only: stage a roll back of the selected methods to a previous version. Nothing is written here.
    [SI.Management.Web.Audit.Audited("template.rollback.stage")]
    public Task<IActionResult> OnPostRollbackAsync(CancellationToken ct) => StageAsync("rollback", Rollback, ct);

    /// #405 -- Admin only: stage the one-click roll back of the Microsoft content to the previous version (only Microsoft
    /// content items; fixes and your business logic are not touched). Nothing is written here.
    [SI.Management.Web.Audit.Audited("template.rollback.stage")]
    public Task<IActionResult> OnPostRollbackMicrosoftAsync(CancellationToken ct) { Scope = "all"; return StageAsync("rollback", Rollback, ct, TemplateClasses.Microsoft); }

    private async Task<IActionResult> StageAsync(string mode, string? version, CancellationToken ct, string? cls = null)
    {
        // template releases are the install's lifecycle: SuperAdmin (#253)
        if (!User.IsSuperAdmin()) return Forbid();
        var r = await _changes.NewTemplateReleaseAsync(mode, version ?? "", Methods, Scope == "all", Reason, ct, cls);
        if (r.Change is not null)
        {
            await _changes.StageAsync(User, r.Change, ct);
            TempData["toast"] = "Staged: " + r.Change.Title + ". Nothing is written until you review and commit.";
            TempData["toastKind"] = "ok";
        }
        else
        {
            TempData["toast"] = "Not staged: " + string.Join("; ", r.Problems);
            TempData["toastKind"] = "error";
        }
        return RedirectToPage(new { pack = mode == "release" ? version : Pack, rollback = mode == "rollback" && cls is null ? version : null });
    }

    /// engine -> its methods, in order
    public static IEnumerable<IGrouping<string, MethodSummary>> ByEngine(ReleaseDiff d) => d.Methods.GroupBy(m => m.Engine, StringComparer.Ordinal);

    public static string Badge(string change) => change switch
    {
        TemplateReleases.Added => "good",
        TemplateReleases.Changed => "warn",
        TemplateReleases.Retired => "bad",
        _ => "",
    };

    public static string Short(string? hash) => string.IsNullOrEmpty(hash) ? "(none)" : hash.Length > 12 ? hash[..12] : hash;
}
