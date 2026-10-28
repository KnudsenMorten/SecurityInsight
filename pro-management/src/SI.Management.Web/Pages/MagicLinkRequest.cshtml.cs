using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Advisors;
using SI.Management.Web.Links;

namespace SI.Management.Web.Pages;

/// <summary>
/// "No work account here? Get a sign-in link" (#258) -- the anonymous page a monthly / per-finding mail links to with the
/// department (and, optionally, the page to open). The person types their mail address; when it is an advisor or a
/// person of that department, a personal sign-in link goes to THAT address (the page never says whether it was). While
/// magic links are off it simply sends the visitor to the department page through the normal sign-in.
/// </summary>
public sealed class MagicLinkRequestModel : PageModel
{
    private readonly DepartmentSignInService _service;
    private readonly WebSettings _web;
    public MagicLinkRequestModel(DepartmentSignInService service, WebSettings web) { _service = service; _web = web; }

    [BindProperty(SupportsGet = true)] public int D { get; set; }
    [BindProperty(SupportsGet = true)] public string? F { get; set; }
    public bool Sent { get; private set; }

    private string Target => DepartmentSignInService.SafeTarget(F, D) ?? DepartmentSignInService.DefaultTarget(D);

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        Response.Headers["Cache-Control"] = "no-store";
        if (D <= 0) return NotFound();
        if (!(await _web.ReadAsync(ct)).MagicLinksEnabled) return LocalRedirect(Target);
        return Page();
    }

    [SI.Management.Web.Audit.Audited("signin.link.request")]
    public async Task<IActionResult> OnPostAsync(string? mail, CancellationToken ct)
    {
        Response.Headers["Cache-Control"] = "no-store";
        if (D <= 0) return NotFound();
        if (!(await _web.ReadAsync(ct)).MagicLinksEnabled) return LocalRedirect(Target);
        await _service.RequestAsync(D, mail, Target, ct);
        Sent = true;
        return Page();
    }
}
