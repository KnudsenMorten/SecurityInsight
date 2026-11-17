using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// "SEARCH THE TENANT" for the people picker (framework GRAPH-PICKER under SECURE-WEB-1; owner 2026-11-16): a name the picker
/// did not find in SecurityInsight's own names is looked up by the ENGINE. Admin and up (the /Admin folder, checked again
/// here); a reason is required; the request is audited (access.directory.search) and written as ONE row through
/// sidata.DirectorySearchAsk, which checks the text and the reason -- there is no limit on how many (owner 2026-11-17); every
/// request is its own audit line, and a request the procedure refuses is audited as refused. The web app makes no Graph call and
/// starts no job: the engine's background job takes the request within about 15 minutes and stores what it finds as names.
/// JSON only -- the pickers (Access, Get started, a department's people) call it; Status answers the asker's own request only.
/// </summary>
public sealed class DirectorySearchModel(DirectorySearchRequests requests, IDirectoryNames names) : PageModel
{
    [BindProperty] public string? Text { get; set; }
    [BindProperty] public string? Reason { get; set; }

    /// Nothing to show: the page is the pickers' endpoint.
    public IActionResult OnGet() => new JsonResult(new { tenantSearch = names.CanAskTenant });

    [SI.Management.Web.Audit.Audited("access.directory.search")]
    public async Task<IActionResult> OnPostAskAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = SI.Management.Web.Audit.AuditScope.Current;
        // the target stays the page (every audit row names its page); the searched text goes with the reason
        if (audit is not null) audit.Reason = Short(Reason, 400) + " -- search: " + Short(Text, 100);
        if (!names.CanAskTenant)
        {
            audit?.Refused("the people picker reads the directory itself on this install");
            return new JsonResult(new { ok = false, message = "Not needed here: the people picker reads the directory itself on this install." });
        }
        var (id, refused) = await requests.AskAsync(Text, Reason, User.ChangeName(), ct);
        if (id is null)
        {
            audit?.Refused(refused);
            return new JsonResult(new { ok = false, message = "Not asked: " + refused });
        }
        return new JsonResult(new { ok = true, id, message = DirectorySearchRequests.AskedWords });
    }

    /// The asker's own request: waiting | done | failed | refused | expired, how many names it found and the engine's words.
    public async Task<IActionResult> OnGetStatusAsync(long id, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var s = await requests.StatusAsync(id, User.ChangeName(), ct);
        return s is null ? new JsonResult(new { state = "unknown" }) : new JsonResult(new { state = s.State, found = s.Found, detail = s.Detail });
    }

    private static string Short(string? s, int n) { var t = (s ?? "").Trim(); return t.Length > n ? t[..n] : t; }
}

/// The picker's note under the search box (Pages/Admin/_PickerNames.cshtml): where its names come from and how fresh they
/// are, and "Search the tenant" when SecurityInsight's engine provides the names.
public sealed record PickerNamesModel(bool FromSecurityInsight, DirectoryFreshness? NamesFrom, bool TenantAsk)
{
    public static PickerNamesModel Of(IDirectoryNames names, DirectoryFreshness? from) => new(names.CanSearch && !names.Enabled, from, names.CanAskTenant);
}
