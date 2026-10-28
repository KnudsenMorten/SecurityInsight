using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.RulePacks;

/// <summary>
/// #462 Rule packs (readers see them; every change checks Admin itself). The CI rule packs of the Pro data model in SQL --
/// the shipped ones and those Invardia delivers through the template channel -- each with its stage (live / testing), its
/// priority and what every rule sets. An Admin turns a pack on or off, stages an Invardia pack (it arrives switched off;
/// staged, it runs as testing: it only proposes), and promotes a testing pack to live after reviewing what it WOULD set
/// (the CIs' rule proposals). Every decision is an override of the pack's header (cfg.ItemOverride, kind 'datamodel',
/// key 'rules/&lt;pack&gt;'), staged on Review &amp; commit and written in the signed-in name. Pro = SQL; no custom files.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly RulePackStore _store;
    private readonly TemplateConformance _conformance;
    private readonly ChangeService _changes;
    private readonly ILogger<IndexModel> _log;

    public IndexModel(RulePackStore store, TemplateConformance conformance, ChangeService changes, ILogger<IndexModel> log)
    { _store = store; _conformance = conformance; _changes = changes; _log = log; }

    /// The pack opened (its header key 'rules/&lt;pack&gt;').
    [BindProperty(SupportsGet = true)] public string? Key { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// Promote only: the Admin confirms having reviewed what the pack would set.
    [BindProperty] public bool Reviewed { get; set; }

    public IReadOnlyList<RulePackView> Packs { get; private set; } = Array.Empty<RulePackView>();
    public RulePackView? Selected { get; private set; }
    public IReadOnlyList<RuleProposal> Proposals { get; private set; } = Array.Empty<RuleProposal>();
    public IReadOnlyDictionary<string, string> States { get; private set; } = new Dictionary<string, string>();
    public bool SchemaMissing { get; private set; }
    public string? Error { get; private set; }
    public string? ProposalError { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            var rows = await _store.RowsAsync(ct);
            if (rows is null) { SchemaMissing = true; return; }
            Packs = RulePackStore.Packs(rows);
            try { States = (await _conformance.ListAsync(DataModelItemValidator.Kind, ct)).Where(r => r.ItemKey.StartsWith("rules/", StringComparison.Ordinal)).ToDictionary(r => r.ItemKey, r => r.Conformance, StringComparer.Ordinal); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the rule pack conformance could not be read"); }
            if (!string.IsNullOrWhiteSpace(Key)) Selected = Packs.FirstOrDefault(p => p.Key == Key);
            if (Selected is not null)
            {
                try { Proposals = await _store.ProposalsAsync(Selected.Rules.Select(r => r.Id).ToList(), ct); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.LogWarning(ex, "the rule proposals could not be read");
                    ProposalError = "What this pack would set could not be read from the CIs: " + ex.Message;
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the rule packs could not be read");
            Error = "The rule packs could not be read from the Pro database: " + ex.Message;
        }
    }

    /// PURE. The header change an action makes -- (stage, enabled), or the reason it does not apply to this pack.
    ///   on       turn a switched-off pack on (an Invardia pack that was never staged goes on as testing)
    ///   off      turn it off: none of its rules runs
    ///   stage    an Invardia pack: on, as testing (it proposes, never decides)
    ///   promote  a testing pack -> live (only after its proposals were reviewed)
    ///   testing  a live pack back to testing
    public static (string? Stage, bool? Enabled, string? Why) Decide(RulePackView p, string action, bool reviewed) => action switch
    {
        "on" when p.Enabled => (null, null, "the pack is already on"),
        "on" => (p.FromInvardia && p.Stage != "production" ? "testing" : null, true, null),
        "off" when !p.Enabled => (null, null, "the pack is already off"),
        "off" => (null, false, null),
        "stage" when !p.FromInvardia => (null, null, "only a pack delivered by Invardia is staged -- turn this one on or off"),
        "stage" when p.Enabled => (null, null, "the pack is already staged"),
        "stage" => ("testing", true, null),
        "promote" when !p.Testing => (null, null, "only a testing pack that is on is promoted to live"),
        "promote" when !reviewed => (null, null, "review what the pack would set first, then tick that you reviewed it"),
        "promote" => ("production", true, null),
        "testing" when !p.Live => (null, null, "only a live pack is put back to testing"),
        "testing" => ("testing", null, null),
        _ => (null, null, $"unknown action '{action}'"),
    };

    public static string Title(RulePackView p, string action) => action switch
    {
        "on" => "Turn on the rule pack " + p.Name,
        "off" => "Turn off the rule pack " + p.Name,
        "stage" => "Stage the Invardia rule pack " + p.Name + " for testing",
        "promote" => "Promote the rule pack " + p.Name + " to live",
        "testing" => "Put the rule pack " + p.Name + " back to testing",
        _ => p.Name,
    };

    /// Admin only: stage one decision on a pack (an override of its header).
    [SI.Management.Web.Audit.Audited("rulepack.decision.stage")]
    public async Task<IActionResult> OnPostDecideAsync(string decision, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.RowsAsync(ct);
        var pack = rows is null ? null : RulePackStore.Packs(rows).FirstOrDefault(p => p.Key == Key);
        if (pack is null) return Toast("Not staged: that rule pack is not in the Pro database", false);
        var (stage, enabled, why) = Decide(pack, decision ?? "", Reviewed);
        if (why is not null) return Toast("Not staged: " + why, false);
        var reason = string.IsNullOrWhiteSpace(Reason) ? Title(pack, decision!) : Reason!.Trim();
        var (change, problems) = await _changes.NewDataModelItemAsync(pack.Key, ItemOverrideRepository.StateOverride, RulePackStore.HeaderWith(pack, stage, enabled), reason, ct);
        if (change is null) return Toast("Not staged: " + string.Join("; ", problems), false);
        var titled = change with { Title = Title(pack, decision!) };
        await _changes.StageAsync(User, titled, ct);
        return Toast("Staged: " + titled.Title + ". Nothing is written until you review and commit.", true);
    }

    /// Admin only: put the shipped header back (the customer's decision on the pack is removed).
    [SI.Management.Web.Audit.Audited("rulepack.reset.stage")]
    public async Task<IActionResult> OnPostResetAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (change, problems) = await _changes.NewDataModelItemAsync(Key ?? "", ItemOverrideRepository.StateInherit, null, string.IsNullOrWhiteSpace(Reason) ? "back to the shipped rule pack" : Reason!.Trim(), ct);
        if (change is null) return Toast("Not staged: " + string.Join("; ", problems), false);
        await _changes.StageAsync(User, change, ct);
        return Toast("Staged: " + change.Title + ". Nothing is written until you review and commit.", true);
    }

    private IActionResult Toast(string text, bool ok)
    {
        TempData["toast"] = text;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage(new { key = Key });
    }

    public static string Badge(string state) => state switch { "live" => "good", "testing" => "warn", _ => "bad" };

    public static string SourceText(string source) => source switch { "invardia" => "Invardia", "customer" => "your own", _ => "SecurityInsight" };
}
