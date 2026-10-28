using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.RiskFactors;

/// <summary>
/// Break glass (emergency-access) accounts -- readers see the rules and the accounts; an Admin changes the rules. Break
/// glass is not a risk factor: it is an SI classification, detected from the platform (an account excluded from all
/// Conditional Access policies, the emergency-access group), from the naming patterns and from the extension attribute
/// and value the customer defines. Two rules are edited here, each a data-model list whose change is that list's
/// cfg.ItemOverride row, staged on Review &amp; commit in the signed-in name:
///   the naming patterns      'lists:break_glass_patterns'   -- validated globs (<see cref="BreakGlassPatterns.Problem"/>)
///   the extension attribute  'lists:break_glass_attribute'  -- attribute=value entries held to the engine's rule
///                                                              (<see cref="BreakGlassAttribute"/>, Parse)
/// No free text reaches a query. The page also lists the accounts classified break glass as of the last data sync, each
/// with the rule that made it so, read from two prepared columns (<see cref="RiskFactorStore.BreakGlassAccountsSql"/>).
/// </summary>
public sealed class BreakGlassModel : PageModel
{
    public const int BlankRows = 5;
    /// Empty rows the attribute form offers for new entries.
    public const int BlankAttributeRows = 2;

    private readonly RiskFactorStore _store;
    private readonly ChangeService _changes;
    private readonly ILogger<BreakGlassModel> _log;

    public BreakGlassModel(RiskFactorStore store, ChangeService changes, ILogger<BreakGlassModel> log) { _store = store; _changes = changes; _log = log; }

    public DataModelRow? List { get; private set; }
    public IReadOnlyList<string> Patterns { get; private set; } = Array.Empty<string>();
    /// "Try a name" (GET, read-only): which patterns match it.
    [BindProperty(SupportsGet = true)] public string? Try { get; set; }
    public IReadOnlyList<string> TryHits { get; private set; } = Array.Empty<string>();
    public bool SchemaMissing { get; private set; }
    public string? Error { get; private set; }

    /// The extension attribute entries in force: the stored text and what it parses to (null = not a valid entry).
    public IReadOnlyList<(string Text, BreakGlassAttribute.Entry? Parsed)> AttributeEntries { get; private set; } = Array.Empty<(string, BreakGlassAttribute.Entry?)>();
    /// The accounts classified break glass as of the last data sync; null = this database cannot list them yet.
    public IReadOnlyList<BreakGlassAccount>? Accounts { get; private set; }
    /// There are more break glass accounts than the page lists.
    public bool MoreAccounts { get; private set; }
    public string? AccountsError { get; private set; }

    /// The listed accounts that carry this entry now (the identity collection found the attribute and value on them).
    public IReadOnlyList<BreakGlassAccount> Carrying(BreakGlassAttribute.Entry entry) =>
        (Accounts ?? Array.Empty<BreakGlassAccount>()).Where(a => BreakGlassAttribute.Carries(entry, a.Attribute)).ToList();

    [BindProperty] public string[]? Pattern { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// The attribute form's rows (Entry[0].Attribute, Entry[0].Value, ...).
    [BindProperty] public List<AttributeInput>? Entry { get; set; }

    /// One row of the attribute form.
    public sealed class AttributeInput
    {
        public string? Attribute { get; set; }
        public string? Value { get; set; }
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            var rows = await _store.ListAsync(ct);
            if (rows is null) { SchemaMissing = true; }
            else
            {
                List = rows.FirstOrDefault(r => r.ItemKey == BreakGlassPatterns.ItemKey);
                Patterns = BreakGlassPatterns.Patterns(InForce(List));
                if (!string.IsNullOrWhiteSpace(Try)) TryHits = Patterns.Where(p => BreakGlassPatterns.Matches(p, Try.Trim())).ToList();
                AttributeEntries = BreakGlassAttribute.Entries(InForce(rows.FirstOrDefault(r => r.ItemKey == BreakGlassAttribute.ItemKey)));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the break glass rules could not be read");
            Error = "The break glass rules could not be read from the Pro database: " + ex.Message;
        }
        // the accounts are their own read: a database that cannot answer it still shows (and changes) the rules
        try
        {
            var accounts = await _store.BreakGlassAccountsAsync(ct);
            if (accounts is not null)
            {
                MoreAccounts = accounts.Count > RiskFactorStore.BreakGlassTop;
                Accounts = accounts.Take(RiskFactorStore.BreakGlassTop).ToList();
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the break glass accounts could not be read");
            AccountsError = "The break glass accounts could not be read from the Pro database: " + ex.Message;
        }
    }

    /// The list body in force: the customer's override, else the shipped one (nothing when the list is switched off).
    private static string? InForce(DataModelRow? row) => row?.Effective ?? (row is { Disabled: true } ? null : row?.TemplateBody);

    /// Admin only: the posted pattern rows (blank rows dropped) become the list's override.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var list = rows.FirstOrDefault(r => r.ItemKey == BreakGlassPatterns.ItemKey);
        var (body, why) = BreakGlassPatterns.WithPatterns(list?.Effective ?? list?.TemplateBody, Pattern ?? Array.Empty<string>());
        if (body is null) return Toast(false, string.Join("; ", why));
        var (change, problems) = await _changes.NewDataModelItemAsync(BreakGlassPatterns.ItemKey, ItemOverrideRepository.StateOverride, body, Reason ?? "", ct);
        if (change is null) return Toast(false, string.Join("; ", problems));
        await _changes.StageAsync(User, change, ct);
        return Toast(true, change.Title);
    }

    /// Admin only: the posted attribute rows (rows with both fields blank dropped) become the override of the list
    /// break_glass_attribute -- the same change record, review and commit as the naming patterns. Every row is held to the
    /// engine's rule here, and again when the change is committed.
    [SI.Management.Web.Audit.Audited("datamodel.item.stage")]
    public async Task<IActionResult> OnPostStageAttributeAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = await _store.ListAsync(ct) ?? Array.Empty<DataModelRow>();
        var list = rows.FirstOrDefault(r => r.ItemKey == BreakGlassAttribute.ItemKey);
        var posted = (Entry ?? new List<AttributeInput>()).Where(e => e is not null).Select(e => (e.Attribute, e.Value));
        var (body, why) = BreakGlassAttribute.WithEntries(list?.Effective ?? list?.TemplateBody, posted);
        if (body is null) return Toast(false, string.Join("; ", why));
        var (change, problems) = await _changes.NewDataModelItemAsync(BreakGlassAttribute.ItemKey, ItemOverrideRepository.StateOverride, body, Reason ?? "", ct);
        if (change is null) return Toast(false, string.Join("; ", problems));
        await _changes.StageAsync(User, change, ct);
        return Toast(true, change.Title);
    }

    private IActionResult Toast(bool ok, string text)
    {
        TempData["toast"] = ok ? "Staged: " + text + ". Nothing is written until you review and commit." : "Not staged: " + text;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage();
    }
}
