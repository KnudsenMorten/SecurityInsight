using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// SECURITY OWNERS (#252, #283): a two-level tree -- every security domain (Endpoint, Identity, Azure, PublicIP, every
/// domain present in the data, and "every domain" (*)) and, under each, the categories the data carries (plus any
/// entered by hand) -- with the people per node. Domain Owners (level 1) and Category Owners (level 2) decide the
/// exemption requests of their scope (the most specific owners are asked) and receive the monthly review; the older
/// approver role (domain level) still decides. A node nobody owns is flagged. People are named by UPN / e-mail. Every
/// add and remove is written with a ChangeLog row and audited. Admin only.
/// </summary>
public sealed class DomainRolesModel : PageModel
{
    private readonly ExemptionWorkflow _flow;
    private readonly IProDataQueries _data;
    private readonly ILogger<DomainRolesModel> _log;
    public DomainRolesModel(ExemptionWorkflow flow, IProDataQueries data, ILogger<DomainRolesModel> log) { _flow = flow; _data = data; _log = log; }

    /// The form's fields -- also pre-filled from a node's "add" link (GET ?domain=..&category=..).
    [BindProperty(SupportsGet = true)] public string? Domain { get; set; }
    [BindProperty(SupportsGet = true)] public string? Category { get; set; }
    [BindProperty] public string? Role { get; set; }
    [BindProperty] public string? Principal { get; set; }

    /// One node of the tree: a domain (Category null) or a category in it, with its people.
    public sealed record Node(string Domain, string? Category, IReadOnlyList<DomainRoleRow> Owners, IReadOnlyList<DomainRoleRow> Approvers,
        IReadOnlyList<string> Deciders, bool InData)
    {
        public bool IsCategory => Category is not null;
        public string Label => DomainRoles.Label(Domain, Category);
        /// Nobody is named on the node itself (a category then falls back to its domain's owners).
        public bool NoOwner => Owners.Count == 0 && (IsCategory || Approvers.Count == 0);
        /// Nobody at all decides it (besides an Admin): no own owner, no domain owner, no approver.
        public bool NobodyDecides => Deciders.Count == 0;
    }

    public Roster Roster { get; private set; } = new(Array.Empty<DomainRoleRow>());
    public IReadOnlyList<string> Domains { get; private set; } = DomainRoles.Known;
    public IReadOnlyList<Node> Tree { get; private set; } = Array.Empty<Node>();
    /// Every category name known (from the data and the roster), for the form's suggestions.
    public IReadOnlyList<string> Categories { get; private set; } = Array.Empty<string>();
    public string? Error { get; private set; }
    /// Said while the latest collection's Domain -> Category pairs are not written by the data sync yet (null = they are).
    public string? CategoriesNotice { get; private set; }

    private static bool Eq(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private async Task LoadAsync(CancellationToken ct)
    {
        try
        {
            if (!await _flow.ReadyAsync(ct)) { Error = "This database does not have the security owner tables yet: run the Pro settings setup (setup\\Import-SIProSettings.ps1 -- it only adds)."; return; }
            Roster = await _flow.RosterAsync(ct);
            var fromData = new List<string>();
            try { if ((await _data.FacetsAsync(ct)).Data.TryGetValue("domain", out var d)) fromData.AddRange(d); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the domains in the data could not be read"); }
            // 2026-10-19: the pairs the data sync wrote for the latest collection (never every finding's DetailJson per request)
            var pairs = await _flow.CategoryPairsAsync(ct);
            CategoriesNotice = await _flow.CategoryPairsWrittenAsync(ct) switch
            {
                false => "The categories in the latest collection's data are being prepared: the data sync works them out once per collection, right after it is loaded. They appear here when that data sync has finished; the categories people own are shown meanwhile.",
                null => "The categories in the data need the database update that adds their table: the updater adds it (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills it. The categories people own are shown meanwhile.",
                _ => null,
            };
            Domains = new[] { DomainRoles.AnyDomain }.Concat(DomainRoles.Known).Concat(fromData.Where(x => !string.IsNullOrWhiteSpace(x)))
                .Concat(pairs.Select(p => p.Domain)).Concat(Roster.Rows.Select(r => r.Domain)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            Tree = Build(Roster, Domains, pairs);
            Categories = pairs.Select(p => p.Category).Concat(Roster.Rows.Where(r => r.IsCategory).Select(r => r.Category!))
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the security owners failed");
            Error = "The security owners could not be read: " + ex.Message;
        }
    }

    /// <summary>
    /// The tree, PURE: each domain, then its categories -- those the data carries and those someone owns -- in name order.
    /// "Every domain" has no categories (a category belongs to one domain).
    /// </summary>
    public static IReadOnlyList<Node> Build(Roster roster, IEnumerable<string> domains, IEnumerable<(string Domain, string Category)> pairs)
    {
        var data = pairs.ToList();
        var list = new List<Node>();
        foreach (var d in domains)
        {
            List<DomainRoleRow> At(string role, string? cat) => roster.Rows.Where(r => r.Role == role && Eq(r.Domain, d)
                && (cat is null ? !r.IsCategory : r.IsCategory && Eq(r.Category, cat))).OrderBy(r => r.Principal, StringComparer.Ordinal).ToList();
            list.Add(new Node(d, null, At(DomainRoles.Owner, null), At(DomainRoles.Approver, null), roster.Deciders(d, null), true));
            if (d == DomainRoles.AnyDomain) continue;
            var cats = data.Where(p => Eq(p.Domain, d)).Select(p => p.Category)
                .Concat(roster.Rows.Where(r => r.IsCategory && Eq(r.Domain, d)).Select(r => r.Category!))
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c, StringComparer.OrdinalIgnoreCase);
            foreach (var c in cats)
                list.Add(new Node(d, c, At(DomainRoles.Owner, c), Array.Empty<DomainRoleRow>(), roster.Deciders(d, c), data.Any(p => Eq(p.Domain, d) && Eq(p.Category, c))));
        }
        return list;
    }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    [SI.Management.Web.Audit.Audited("domainrole.member.add")]
    public Task<IActionResult> OnPostAddAsync(CancellationToken ct) => SetAsync(true, ct);
    [SI.Management.Web.Audit.Audited("domainrole.member.remove")]
    public Task<IActionResult> OnPostRemoveAsync(CancellationToken ct) => SetAsync(false, ct);

    private async Task<IActionResult> SetAsync(bool add, CancellationToken ct)
    {
        var r = await _flow.SetRoleAsync(User, add, Domain ?? "", Category, Role ?? "", Principal ?? "", ct);
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Status switch { WriteStatus.Saved => "ok", WriteStatus.Stale => "warn", _ => "error" };
        return Redirect("/Admin/DomainRoles");
    }
}
