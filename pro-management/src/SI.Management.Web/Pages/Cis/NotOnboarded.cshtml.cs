using System.Globalization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Cis;

/// <summary>
/// #858 ACTIVE DEVICES NOT ONBOARDED IN DEFENDER (owner 2026-10-21: "it would make sense to have a view to show them - Active
/// devices not onboarded in Defender (both MDC/MDE)"): the active device CIs Defender for Endpoint only discovered on the
/// network (can be onboarded / unsupported / insufficient info) and the Azure machines Defender for Cloud lists without the
/// agent -- split by status, with name (a nameless device by its IP / MAC address, marked, #856), IP, MAC, OS, first / last
/// seen and the source. Active only (the lifecycle's seen window, from the settings); a device a customer excluded by tag is
/// not listed (the count says how many). The executive coverage figure "Devices not onboarded" links here.
/// </summary>
public sealed class NotOnboardedModel(INotOnboardedViews views, ILogger<NotOnboardedModel> log) : PageModel
{
    public const string Route = "/Cis/NotOnboarded";

    public NotOnboardedPage? Data { get; private set; }
    public QueryInfo? Query { get; private set; }
    public string? Error { get; private set; }
    public CiLifecycleRules Lifecycle { get; private set; } = CiLifecycleDefinitions.Defaults;
    /// The status the request names (null = every status).
    public string? Status { get; private set; }

    /// The page with a status / page / size (null keeps the request's value; a status change starts at page 1).
    public string Link(string? status = null, int? page = null, int? size = null, bool allStatuses = false)
    {
        var st = allStatuses ? null : status ?? Status;
        var parts = new List<string>();
        if (st is not null) parts.Add("status=" + Uri.EscapeDataString(st));
        var sz = size ?? Data?.Size ?? NotOnboarded.Sizes[0];
        if (sz != NotOnboarded.Sizes[0]) parts.Add("size=" + sz.ToString(CultureInfo.InvariantCulture));
        var p = page ?? (status is null && !allStatuses && size is null ? Data?.Page ?? 1 : 1);
        if (p > 1) parts.Add("p=" + p.ToString(CultureInfo.InvariantCulture));
        return Route + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    /// The CI list filtered to one Defender onboarding state (its "+ Add filter" on the onboarding column) -- the columns,
    /// the export; null for a status the CI list cannot filter on (an Azure machine without the agent has no state).
    public static string? CiListLink(string status) =>
        status is NotOnboarded.CanBeOnboarded or NotOnboarded.Unsupported or NotOnboarded.InsufficientInfo
            ? "/Cis/Index?class=device&f.OnboardingStatus=" + Uri.EscapeDataString(status) : null;

    public async Task OnGetAsync(string? status, int? p, int? size, CancellationToken ct)
    {
        Status = NotOnboarded.Status(status);
        var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        if (resolver is not null && (await resolver.ResolveAsync(User, ct)).Rows is not null)
        {
            Error = "This view is not available to an account limited to departments: it shows devices across every department.";
            return;
        }
        // the seen window in force (the same reader every CI view says its lifecycle with)
        try { if (HttpContext?.RequestServices.GetService<ICiLifecycleRulesReader>() is { } lr) Lifecycle = await lr.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the lifecycle settings could not be read; the defaults are shown"); }
        try
        {
            var r = await views.ReadAsync(Status, p ?? 1, size ?? NotOnboarded.Sizes[0], ct);
            Data = r.Data;
            if (r.Query.Length > 0) Query = QueryInfo.From(r, "Active devices not onboarded");
        }
        catch (ViewTimeoutException ex) { Error = SI.Management.Web.Pages.Collection.CollectionPageModel.TimeoutText(ex.Limit, null); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "the devices not onboarded could not be read");
            Error = "The devices could not be read from the Pro database: " + ex.Message;
        }
    }

    /// "What you're looking at": active devices only (the seen window in force), the excluded ones left out.
    public ViewScope Scope => new()
    {
        LifecycleDefaulted = true,
        Lifecycle = string.Create(CultureInfo.InvariantCulture, $"Active devices only: a source saw them within the last {CiLifecycleRules.Days(Lifecycle.SeenWithinDays)} -- a not seen or retired device is never listed or counted here"),
        Defaults = Data is { Ready: true, Excluded: > 0 } d
            ? new[] { Fmt.Int(d.Excluded) + " more excluded by your tag (asset tagging) -- not listed, not counted" }
            : Array.Empty<string>(),
        Definitions = Lifecycle.Definitions.Concat(NotOnboarded.Statuses.Select(s => (s.Label, s.Meaning))).ToList(),
    };
}
