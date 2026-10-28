using System.Globalization;
using System.Reflection;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Exemptions;

/// <summary>
/// Which setting decides, by default, whether a page shows and counts exempted findings (#264):
/// <list type="bullet">
/// <item><see cref="Views"/> -- SIWeb_Exempted_ShowInViews: the findings browser, the collection views, the asset page,
/// the CMDB pages (the rows are hidden or shown, marked);</item>
/// <item><see cref="Management"/> -- SI_Exempted_CountInManagement: the management dashboards, trends, closure, the
/// Services view and the wall board (the numbers leave them out or count them);</item>
/// <item><see cref="Departments"/> -- SI_Exempted_InDepartmentReports: the department pages (and, in PowerShell, the
/// department mails).</item>
/// </list>
/// </summary>
public enum ExemptedSurface { Views, Management, Departments }

/// <summary>
/// Marks a page as one that shows exempted findings: a GET of it runs under the exempted scope its surface's setting
/// gives, overridden by the view's tick (<c>?exempted=1</c> / <c>?exempted=0</c>), and the layout shows the tick and the
/// "N exempted not counted" note. <see cref="NoTick"/>: the setting only (the wall board -- a kiosk).
/// </summary>
[AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = false)]
public sealed class ExemptedSurfaceAttribute(ExemptedSurface surface) : Attribute
{
    public ExemptedSurface Surface { get; } = surface;
    public bool NoTick { get; init; }
    /// A page under a marked base that shows no finding (the close-loop events, the connector runs): no scope, no tick.
    public bool Off { get; init; }
}

/// Whether the database carries the exemption mark and the counted twins (sql\si-data-schema.sql, #264). Until it does,
/// no read is rewritten and the pages count as before (a database without the mark never had exempted rows in it).
public interface IExemptedSchema
{
    Task<bool> ReadyAsync(CancellationToken ct);
}

public sealed class SqlExemptedSchema(ISqlExecutor sql, IMemoryCache cache, ILogger<SqlExemptedSchema> log) : IExemptedSchema
{
    public async Task<bool> ReadyAsync(CancellationToken ct)
    {
        if (cache.TryGetValue("si-exempted-schema", out bool hit)) return hit;
        bool ready;
        try
        {
            var rows = await sql.QueryAsync(Exempted.SchemaReadySql, new Dictionary<string, object?>(), ct);
            ready = rows.FirstOrDefault()?.Long("Ready") == 1;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the exemption mark could not be checked -- reads are not rewritten");
            ready = false;
        }
        cache.Set("si-exempted-schema", ready, TimeSpan.FromMinutes(ready ? 10 : 2));
        return ready;
    }
}

/// <summary>What a page shows about exempted findings -- the tick, the note, the "simulated" label. In HttpContext.Items.</summary>
public sealed record ExemptedView(ExemptedSurface Surface, bool Ready, bool Include, bool SettingDefault, bool FromTick, bool NoTick, long? NotCounted,
    string ShowUrl, string HideUrl)
{
    public const string ItemKey = "si-exempted-view";

    /// A numbers page whose tick includes exempted findings: the figures are a SIMULATION (never saved, the setting unchanged).
    public bool Simulated => Include && FromTick && Surface != ExemptedSurface.Views && !SettingDefault;

    /// The tick's label: a view shows rows, a numbers page includes them in its figures.
    public string TickLabel => Surface == ExemptedSurface.Views ? "Show exempted" : "Include exempted";

    /// The value to carry on links and forms ("1" / "0") when the tick decided, else null.
    public string? Carry => FromTick ? (Include ? "1" : "0") : null;

    public static ExemptedView? Of(HttpContext? http) => http?.Items.TryGetValue(ItemKey, out var v) == true ? v as ExemptedView : null;
}

/// <summary>The per-view tick in the URL, and the links that set or carry it.</summary>
public static class ExemptedTick
{
    /// The tick: true = show / include, false = hide / leave out, null = not set (the setting decides).
    public static bool? Read(IQueryCollection query) => ((string?)query[Exempted.QueryKey])?.Trim() switch
    {
        "1" or "true" or "on" => true,
        "0" or "false" or "off" => false,
        _ => null,
    };

    /// The scope a surface's setting and the view's tick give: the tick wins, for this view only.
    public static ExemptedScope Resolve(bool settingDefault, bool? tick) => new(tick ?? settingDefault, tick is not null);

    /// This page's URL with the tick set (and paging / a handler dropped: a new population starts at page 1).
    public static string Toggle(HttpRequest request, bool include)
    {
        var parts = new List<string>();
        foreach (var kv in request.Query)
        {
            if (kv.Key.Equals(Exempted.QueryKey, StringComparison.OrdinalIgnoreCase) || kv.Key.Equals("handler", StringComparison.OrdinalIgnoreCase)
                || kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add(Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(v));
        }
        parts.Add(Exempted.QueryKey + "=" + (include ? "1" : "0"));
        return request.Path + "?" + string.Join("&", parts);
    }

    /// A link inside the app with the view's tick carried (unchanged when there is no tick, when the link already sets it,
    /// or when it leaves the app) -- so a drill-down shows the same population.
    public static string Carry(string url, string? value)
    {
        if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(url) || !url.StartsWith('/') || url.StartsWith("//", StringComparison.Ordinal)) return url;
        var q = url.IndexOf('?');
        var hash = url.IndexOf('#');
        var head = hash >= 0 ? url[..hash] : url;
        var tail = hash >= 0 ? url[hash..] : "";
        if (q >= 0 && head[(q + 1)..].Split('&').Any(p => p.StartsWith(Exempted.QueryKey + "=", StringComparison.OrdinalIgnoreCase))) return url;
        return head + (q >= 0 ? "&" : "?") + Exempted.QueryKey + "=" + value + tail;
    }

    /// <see cref="Carry(string, string?)"/> with the current request's tick.
    public static string Carry(HttpContext? http, string url) => Carry(url, ExemptedView.Of(http)?.Carry);
}

/// <summary>
/// THE page filter of #264: a GET of a page marked <see cref="ExemptedSurfaceAttribute"/> runs under the exempted scope of
/// its surface's setting -- overridden by the view's tick -- so every read the page makes (and its Excel / CSV export)
/// shows the same population. Only where the database carries the mark; elsewhere nothing is rewritten.
/// </summary>
public sealed class ExemptedPageFilter(ExemptionSettings settings, IExemptedSchema schema, ISqlExecutor sql, IMemoryCache cache, ILogger<ExemptedPageFilter> log) : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var http = context.HttpContext;
        var attr = context.HandlerInstance?.GetType().GetCustomAttribute<ExemptedSurfaceAttribute>(inherit: true);
        if (attr is null || attr.Off || !HttpMethods.IsGet(http.Request.Method)) { await next(); return; }
        var ct = http.RequestAborted;
        var s = await settings.ReadAsync(ct);
        var def = attr.Surface switch
        {
            ExemptedSurface.Views => s.ShowInViews,
            ExemptedSurface.Management => s.CountInManagement,
            _ => s.InDepartmentReports,
        };
        var tick = attr.NoTick ? null : ExemptedTick.Read(http.Request.Query);
        var scope = ExemptedTick.Resolve(def, tick);
        var ready = await schema.ReadyAsync(ct);
        long? notCounted = null;
        if (ready && !scope.Include) notCounted = await CountAsync(http, attr.Surface, ct);
        http.Items[ExemptedView.ItemKey] = new ExemptedView(attr.Surface, ready, scope.Include, def, scope.FromTick, attr.NoTick, notCounted,
            ExemptedTick.Toggle(http.Request, true), ExemptedTick.Toggle(http.Request, false));
        using (Exempted.Use(ready ? scope : null)) await next();
    }

    /// The exempted findings of the page's collection (?c=, else the newest) -- of the department for a department page
    /// (?id=). Not shown to an account limited to departments on an estate-wide page (it would count other departments).
    private async Task<long?> CountAsync(HttpContext http, ExemptedSurface surface, CancellationToken ct)
    {
        var c = ((string?)http.Request.Query["c"])?.Trim();
        string? dept = surface == ExemptedSurface.Departments ? ((string?)http.Request.Query["id"])?.Trim() : null;
        if (c is { Length: > 0 } && ProDataFilters.Id(c, "collection") is null) c = null;
        if (dept is { Length: > 0 } && !int.TryParse(dept, NumberStyles.None, CultureInfo.InvariantCulture, out _)) dept = null;
        if (dept is null)
        {
            var resolver = http.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
            if (resolver is not null && (await resolver.ResolveAsync(http.User, ct)).Rows is not null) return null;
        }
        var key = "si-exempted-count|" + (c ?? "-") + "|" + (dept ?? "-");
        if (cache.TryGetValue(key, out long hit)) return hit;
        try
        {
            var rows = await sql.QueryAsync(Exempted.CountSql, new Dictionary<string, object?> { ["CollectionId"] = string.IsNullOrEmpty(c) ? null : c, ["DepartmentId"] = string.IsNullOrEmpty(dept) ? null : dept }, ct);
            var n = rows.FirstOrDefault()?.Long("N") ?? 0L;
            cache.Set(key, n, TimeSpan.FromMinutes(2));
            return n;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the exempted findings could not be counted");
            return null;
        }
    }
}

/// <summary>
/// The bulk guard of #264: "request an exemption for all N matching" is offered -- and accepted by the server -- only when
/// the filter NARROWS the set beyond the bare collection AND N is at most SIWeb_Exemption_BulkMax. A whole collection is
/// never exempted in one go.
/// </summary>
public static class ExemptionBulkGuard
{
    public sealed record Verdict(bool Allowed, string? Reason);

    /// Whether the findings browser's filter narrows the collection (any of tier, severity, domain, report, kind, search).
    public static bool Narrows(params string?[] filters) => filters.Any(f => !string.IsNullOrWhiteSpace(f));

    public static Verdict Check(bool narrowed, long matching, int max)
    {
        if (!narrowed)
            return new(false, "A request for every finding needs a filter that narrows the collection first -- pick a severity, a domain, a report, an asset kind, a column filter or a search. A whole collection is never exempted in one go.");
        if (matching > max)
            return new(false, $"{Fmt.Int(matching)} findings match -- at most {Fmt.Int(max)} can be requested in one go (SIWeb_Exemption_BulkMax). Narrow the filter, or select the findings.");
        if (matching <= 0) return new(false, "No finding matches this filter.");
        return new(true, null);
    }
}
