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
            Error = "The profiling rules could not be read from the Pro database: " + ViewerError.Text(ex);
        }
    }

    /// The section of the rules that use no condition kind at all (a rule whose text holds no 'kind:').
    public const string NoKind = "(no condition kind)";

    public sealed record KindGroup(string Kind, IReadOnlyList<RuleEntry> Rules);

    /// <summary>
    /// #1351 (owner 2026-11-24: "a collapsed sorting per KIND (grouped)" / "i said the kind method"): the rules table in one
    /// section per condition kind -- the values of the Condition kinds column. A rule with several kinds is under each of
    /// them; a rule with none under <see cref="NoKind"/> (last). The sections in kind order, the rules in each in the
    /// catalog's order (by rule, as the table was before). PURE: built from the catalog the page already read.
    /// </summary>
    public static IReadOnlyList<KindGroup> ByKind(IEnumerable<RuleEntry> rules)
    {
        var groups = new SortedDictionary<string, List<RuleEntry>>(StringComparer.OrdinalIgnoreCase);
        var none = new List<RuleEntry>();
        foreach (var r in rules)
        {
            if (r.Summary.Kinds.Count == 0) { none.Add(r); continue; }
            foreach (var k in r.Summary.Kinds.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!groups.TryGetValue(k, out var list)) groups[k] = list = new List<RuleEntry>();
                list.Add(r);
            }
        }
        var outList = groups.Select(g => new KindGroup(g.Key, g.Value)).ToList();
        if (none.Count > 0) outList.Add(new KindGroup(NoKind, none));
        return outList;
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
