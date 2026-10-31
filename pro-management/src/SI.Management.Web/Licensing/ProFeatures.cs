using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Changes;
using SI.Management.Web.Navigation;

namespace SI.Management.Web.Licensing;

/// <summary>
/// ONE WEB APP, BOTH VERSIONS (owner 2026-10-18, SI #750 (a); #480): the free version runs this web app too, and the paid
/// features are switched OFF BY THE LICENCE -- never left out as files. This is the one list of what is paid in the web app:
/// the Razor pages (by their page path, a folder covers every page under it) and the actions of the shared action bar.
/// Everything not listed is in both versions. The licence decides through <see cref="IProLicence"/>; the refusal is
/// SERVER-SIDE (<see cref="ProFeaturePageFilter"/> on every page and handler, <see cref="FindingActions.FindingActionRegistry"/>
/// for the actions) -- the menu only hides what would be refused anyway.
/// THE SPLIT (#480, "free = see your risk, Pro = work on it"): free = the collection, the CIs, Risk Analysis and every
/// view of it, settings, jobs, run health, the risk index, rules and outputs. Paid = governance (exemptions, departments,
/// tasks, security owners), the CMDB and its connectors (with the vulnerability close-loop), mail alerts and management
/// summary mails, the role and scope mapping, the audit trail, templates with rings, and the AI chat.
/// </summary>
public static class ProFeatures
{
    public const string Governance = "governance", CmdbConnectors = "cmdb-connectors", Alerts = "alerts", Access = "access",
        Audit = "audit", Templates = "templates", Ai = "ai",
        // the management presentation (PowerPoint): the Community edition keeps the Executive report's PDF print
        Presentation = "presentation",
        // the licence request to Invardia (Get Started's licence step): no licence to ask about without Pro
        Licence = "licence";

    /// The words a person reads for each paid feature (the "part of SecurityInsight Pro" page).
    public static readonly IReadOnlyDictionary<string, string> Titles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [Governance] = "Exemptions, departments, follow-up tasks and security owners",
        [CmdbConnectors] = "The CMDB, its connectors and the vulnerability close-loop",
        [Alerts] = "Mail alerts and management summary mails",
        [Access] = "Roles and scopes for people and groups",
        [Audit] = "The audit trail",
        [Templates] = "Template releases, conformance and deviations",
        [Ai] = "Ask about your estate (the AI chat)",
        [Presentation] = "Management presentations (PowerPoint)",
        [Licence] = "The licence request to Invardia",
    };

    /// Page path (a folder, or one page) -> the paid feature. The most specific path wins.
    public static readonly IReadOnlyDictionary<string, string> Pages = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["/Exemptions"] = Governance,
        ["/Departments"] = Governance,
        ["/Tasks"] = Governance,
        ["/Admin/Tasks"] = Governance,
        ["/Admin/Departments"] = Governance,
        ["/Admin/DomainRoles"] = Governance,
        ["/Cmdb"] = CmdbConnectors,
        ["/Collection/Services"] = CmdbConnectors,
        ["/Collection/Connectors"] = CmdbConnectors,
        ["/Admin/Connectors"] = CmdbConnectors,
        ["/Admin/ConnectorSetup"] = CmdbConnectors,
        ["/Admin/CloseLoop"] = CmdbConnectors,
        ["/Admin/Resend"] = CmdbConnectors,
        // Configuration > Connectors (owner 2026-10-19, after the free branch): the fields and the scope the CMDB / ServiceNow /
        // SQL vulnerability connectors send -- connector configuration, so the same feature as the connectors themselves
        ["/Connectors"] = CmdbConnectors,
        ["/Admin/Settings/Reports"] = Alerts,
        ["/Admin/Settings/Notifications"] = Alerts,
        ["/Admin/Access"] = Access,
        ["/Admin/History"] = Audit,
        ["/Templates"] = Templates,
        ["/Admin/Deviations"] = Templates,
        ["/Chat"] = Ai,
        ["/Management/Presentation"] = Presentation,
    };

    /// The actions of the shared action bar that are paid: every governance action. Export stays in both versions.
    public static readonly IReadOnlyDictionary<string, string> Actions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["exemption-request"] = Governance,
        ["comment"] = Governance,
        ["status"] = Governance,
        ["task"] = Governance,
        ["escalate-vendor"] = Governance,
        ["assign-department"] = Governance,
    };

    /// The paid feature of a Razor page ("/Exemptions/Index", "/Admin/Departments/Edit"), or null when it is in both versions.
    public static string? ForPage(string? page)
    {
        var p = (page ?? "").Trim().TrimEnd('/');
        if (p.Length == 0) return null;
        string? best = null; var bestLen = -1;
        foreach (var (path, feature) in Pages)
        {
            var hit = p.Equals(path, StringComparison.OrdinalIgnoreCase) || p.StartsWith(path + "/", StringComparison.OrdinalIgnoreCase);
            if (hit && path.Length > bestLen) { best = feature; bestLen = path.Length; }
        }
        return best;
    }

    /// The paid feature of a finding action by its key, or null when it is in both versions.
    public static string? ForAction(string? key) => key is not null && Actions.TryGetValue(key.Trim(), out var f) ? f : null;

    /// The page a menu item opens for this person: its own page, or -- for an item with tabs -- the first tab that is open
    /// to them (<paramref name="open"/>). null = nothing of the item is open.
    public static string? FirstOpenPage(NavItem item, Func<string, string, bool> open)
    {
        if (item.Tabs is { Count: > 0 } tabs) return tabs.FirstOrDefault(t => open(t.Page, t.Need))?.Page;
        return open(item.Page, item.Need) ? item.Page : null;
    }

    /// The "part of SecurityInsight Pro" page for a feature.
    public static string ProOnlyUrl(string feature) => "/ProOnly?feature=" + Uri.EscapeDataString(feature);

    /// The one sentence a refused request carries.
    public static string RefusalText(string feature) =>
        (Titles.TryGetValue(feature, out var t) ? t : feature) + " is part of SecurityInsight Pro: this installation has no Pro licence, so nothing was done." + InstalledLicence.LicenceRoute;
}

/// <summary>
/// Is this installation licensed for the paid features? The installed licence as the updater verified it
/// (cfg.InstallState 'Licence', <see cref="InstalledLicenceReader"/>) -- the same record and the same rule as the header's
/// Licence group (<see cref="LicenceDimension.Of"/>: Pro while the licence is valid, ends soon or is in grace, AND its signed
/// sku names a Pro edition). DENY BY DEFAULT: no record, a record that does not read, a database that does not answer =
/// not Pro. Kept for a minute (the licence is verified nightly).
/// </summary>
public interface IProLicence
{
    Task<bool> IsProAsync(CancellationToken ct);
}

public sealed class InstalledProLicence(InstalledLicenceReader reader, IMemoryCache cache, ILogger<InstalledProLicence> log) : IProLicence
{
    public const string CacheKey = "si:licence:pro";
    public static readonly TimeSpan Keep = TimeSpan.FromMinutes(1);

    public async Task<bool> IsProAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(CacheKey, out bool known)) return known;
        var pro = false;
        try { pro = Decide(await reader.ReadAsync(ct), DateTime.UtcNow); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // could not read = not Pro (deny by default); said in the log, never an error page
            log.LogWarning(ex, "The installed licence could not be read; the paid features are refused until it can.");
            pro = false;
        }
        cache.Set(CacheKey, pro, Keep);
        return pro;
    }

    /// PURE. Pro = a recorded licence whose dimension is not Community (valid / ends soon / in grace, a Pro sku); else not.
    public static bool Decide(InstalledLicence? licence, DateTime todayUtc) =>
        licence is not null && LicenceDimension.Of(licence, todayUtc) != LicenceDimension.Community;
}

/// <summary>
/// THE SERVER-SIDE REFUSAL of a paid page without a Pro licence -- on every Razor page and every handler of it, GET and
/// POST alike, before the handler runs. A page view (GET / HEAD) goes to the "part of SecurityInsight Pro" page; anything
/// else is answered 403 with the reason (JSON for a script, a short page otherwise) and nothing is done.
/// </summary>
public sealed class ProFeaturePageFilter(IProLicence licence) : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var feature = ProFeatures.ForPage(context.ActionDescriptor.ViewEnginePath);
        if (feature is null || await licence.IsProAsync(context.HttpContext.RequestAborted)) { await next(); return; }
        context.Result = Refuse(context.HttpContext.Request, feature);
    }

    public static IActionResult Refuse(HttpRequest request, string feature)
    {
        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method)) return new RedirectResult(ProFeatures.ProOnlyUrl(feature));
        var message = ProFeatures.RefusalText(feature);
        if (request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase))
            return new JsonResult(new { ok = false, pro = true, feature, message }) { StatusCode = StatusCodes.Status403Forbidden };
        var html = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" /><title>Part of SecurityInsight Pro</title>"
                 + "<link rel=\"stylesheet\" href=\"/css/site.css\" /></head><body><main id=\"main\"><h1>Part of SecurityInsight Pro</h1>"
                 + $"<div class=\"notice warn\" role=\"alert\" data-pro-refused=\"{WebUtility.HtmlEncode(feature)}\">{WebUtility.HtmlEncode(message)}</div>"
                 + "<p><a href=\"/\">Back to your start page</a></p></main></body></html>";
        return new ContentResult { StatusCode = StatusCodes.Status403Forbidden, ContentType = "text/html; charset=utf-8", Content = html };
    }
}
