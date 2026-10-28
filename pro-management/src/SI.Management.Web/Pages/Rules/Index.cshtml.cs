using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Rules;

/// <summary>
/// Configuration > Profiling rules (#275 G8): every asset-profiling rule the next run applies -- the vendor's, the ones
/// you changed or turned off, and your own -- with what each one detects and which tier it sets. Readers see the list
/// and each rule's text; an Admin opens a rule to change it (form or YAML), turns it off, resets it, or adds a rule.
/// Nothing is written on these pages: every change goes through Review &amp; commit.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly RuleItemStore _store;
    private readonly ILogger<IndexModel> _log;
    public IndexModel(RuleItemStore store, ILogger<IndexModel> log) { _store = store; _log = log; }

    public RuleCatalog? Catalog { get; private set; }
    public string? Error { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { Catalog = await _store.LoadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the profiling rules could not be read");
            Error = "The profiling rules could not be read from the Pro database: " + ex.Message;
        }
    }

    public static string OriginLabel(RuleOrigin o) => o switch
    {
        RuleOrigin.Vendor => "vendor",
        RuleOrigin.Changed => "changed",
        RuleOrigin.Off => "turned off",
        _ => "yours",
    };

    public static string OriginClass(RuleOrigin o) => o switch { RuleOrigin.Vendor => "good", RuleOrigin.Changed => "warn", RuleOrigin.Off => "bad", _ => "" };
}
