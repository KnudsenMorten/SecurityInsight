using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// #1053 Operations > Data quality > Correlation suspects (readers see it; every decision checks Admin itself). The
/// correlation gatekeeper's current finding -- written by each data sync (sidata.CiSuspect): CIs that are probably ONE
/// machine (one hard id on two active CIs; the same short name / FQDN label on 2-3 server / VM CIs) and devices with a
/// placeholder name, each group with every CI by name, its tier, findings and links, the evidence and the tier impact.
/// An Admin decides, with a reason, through Review &amp; commit (CorrelationDecisionChanges): "the same machine" -- the next
/// CI build merges them; "not the same machine" -- no longer warned about; and removes a decision (a "same" one is split
/// again). A warning only: nothing here blocks a run or a hand-off.
/// </summary>
public sealed class CorrelationSuspectsModel : PageModel
{
    private readonly CorrelationSuspectStore _store;
    private readonly CorrelationDecisionChanges _changes;
    private readonly ChangeService _service;
    private readonly ILogger<CorrelationSuspectsModel> _log;

    public CorrelationSuspectsModel(CorrelationSuspectStore store, CorrelationDecisionChanges changes, ChangeService service, ILogger<CorrelationSuspectsModel> log)
    { _store = store; _changes = changes; _service = service; _log = log; }

    /// Show the groups a person already decided about too (off = only the ones to look at).
    [BindProperty(SupportsGet = true, Name = "decided")] public bool ShowDecided { get; set; }
    /// Decide: the verdict (same | not_same), the group and its CIs, the reason.
    [BindProperty] public string? Verdict { get; set; }
    [BindProperty] public string? GroupKey { get; set; }
    [BindProperty] public string? CiIds { get; set; }
    [BindProperty] public string? Names { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public IReadOnlyList<CorrelationSuspectGroup> Groups { get; private set; } = Array.Empty<CorrelationSuspectGroup>();
    public IReadOnlyList<CorrelationDecisionRow> Decisions { get; private set; } = Array.Empty<CorrelationDecisionRow>();
    public bool TableMissing { get; private set; }
    public string? Error { get; private set; }
    public DateTime? ComputedAt { get; private set; }

    /// The groups shown: the ones to look at, or all with the switch on.
    public IReadOnlyList<CorrelationSuspectGroup> Shown => ShowDecided ? Groups : Groups.Where(g => !g.Dismissed).ToList();
    public int Open => Groups.Count(g => !g.Dismissed);
    public int Decided => Groups.Count(g => g.Dismissed);
    public int TierConflicts => Groups.Count(g => !g.Dismissed && g.TierConflict);

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            if (!await _store.TableExistsAsync(ct)) { TableMissing = true; return; }
            Groups = await _store.ListAsync(ct);
            Decisions = await _store.DecisionsAsync(ct);
            ComputedAt = Groups.SelectMany(g => g.Members).Select(m => m.ComputedAt).Where(d => d is not null).DefaultIfEmpty(null).Max();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the correlation suspects could not be read");
            Error = "The correlation suspects could not be read from the Pro database: " + ViewerError.Text(ex);
        }
    }

    /// The rule in words.
    public static string RuleText(string rule) => rule switch
    {
        CorrelationSuspectStore.RuleHardId => "One hard id on two or more active CIs",
        CorrelationSuspectStore.RuleName => "The same name on 2-3 server / VM CIs",
        CorrelationSuspectStore.RulePlaceholder => "A placeholder name",
        _ => rule,
    };

    /// The role of a CI in its group, in words ("" = none).
    public static string RoleText(string? role) => role switch
    {
        "leftover" => "no source sees it any more",
        "unanchored" => "no hard device id",
        _ => "",
    };

    public static string SeverityBadge(string severity) => severity switch { "high" => "bad", "medium" => "warn", _ => "info" };

    /// PURE. The tier impact of a group in words ("" when its CIs agree): which CI carries the most critical tier, and the
    /// tier of the CI with the most findings.
    public static string Impact(CorrelationSuspectGroup g)
    {
        if (!g.TierConflict || g.Rule == CorrelationSuspectStore.RulePlaceholder) return "";
        static string Name(CorrelationSuspectRow m) => string.IsNullOrWhiteSpace(m.Name) ? m.CiId : m.Name!;
        static string TierWords(CorrelationSuspectRow m) => m.Tier is { } t ? "Tier " + t : "no tier";
        static string Findings(CorrelationSuspectRow m) => m.OpenFindings is { } f ? Fmt.Int(f) + " finding" + (f == 1 ? "" : "s") : "findings not counted yet";
        var top = g.Members.Where(m => m.Tier is not null).OrderBy(m => m.Tier).ThenBy(m => m.OpenFindings ?? 0).FirstOrDefault();
        var most = g.Members.OrderByDescending(m => m.OpenFindings ?? -1).ThenBy(m => m.Tier ?? 9).First();
        if (top is null || top.CiId == most.CiId) return "The CIs carry different tiers: " + string.Join("; ", g.Members.Select(m => $"{Name(m)} is {TierWords(m)} ({Findings(m)})")) + ".";
        return $"{TierWords(top)} is on {Name(top)} ({Findings(top)}); {Name(most)} ({Findings(most)}) is {TierWords(most)} -- the most critical tier may sit on the wrong CI.";
    }

    /// Admin only: stage a decision about one group's CIs.
    [SI.Management.Web.Audit.Audited("cisuspect.decide.stage")]
    public async Task<IActionResult> OnPostDecideAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var ids = (CiIds ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var (change, why) = await _changes.NewDecisionAsync(Verdict, ids, GroupKey, Names, Reason, ct);
        return await StageAsync(change, why, ct);
    }

    /// Admin only: stage the removal (soft) of one decision -- a "same" one is split again.
    [SI.Management.Web.Audit.Audited("cisuspect.remove.stage")]
    public async Task<IActionResult> OnPostRemoveAsync(long id, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (change, why) = await _changes.NewRemoveAsync(id, Reason, ct);
        return await StageAsync(change, why, ct);
    }

    private async Task<IActionResult> StageAsync(StagedChange? change, IReadOnlyList<string> why, CancellationToken ct)
    {
        if (change is not null)
        {
            await _service.StageAsync(User, change, ct);
            TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
            TempData["toastKind"] = "ok";
        }
        else
        {
            TempData["toast"] = "Not staged: " + string.Join("; ", why);
            TempData["toastKind"] = "error";
        }
        return RedirectToPage(new { decided = ShowDecided ? "true" : null });
    }
}
