using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Audit;

/// <summary>
/// THE web half of the audit trail (#260, AUDIT-1.2 / 1.5): a global page filter that writes EXACTLY ONE 'event' row for
/// every request to a mutating handler (POST / PUT / PATCH / DELETE) and for every handler marked <see cref="AuditedAttribute"/>
/// (the exports, the magic-link redeemer, the audit print view) -- on success, on refusal and on error. The action is
/// the handler's <see cref="AuditedAttribute"/>; a mutating handler without one is written as <c>web.handler.unlisted</c>
/// (a coverage test keeps that at zero) unless it carries <see cref="NotAuditedAttribute"/> (a closed list, each with its
/// reason). While the handler runs, its <see cref="AuditScope"/> is ambient: the SQL executor stamps the correlation id
/// into SESSION_CONTEXT so every cfg.ChangeLog row the handler writes (via the trigger) joins this event, and the role
/// framework notes the target's domain / department. The write happens after the handler; a failed write never changes
/// the response (it is logged and counted in <see cref="AuditHealth"/>).
/// </summary>
public sealed class AuditPageFilter : IAsyncPageFilter, IAsyncAlwaysRunResultFilter
{
    public const string Unlisted = "web.handler.unlisted";
    private readonly IAuditWriter _writer;
    private readonly ILogger<AuditPageFilter> _log;
    private readonly ISignedRequestWriter? _signed;
    public AuditPageFilter(IAuditWriter writer, ILogger<AuditPageFilter> log, ISignedRequestWriter? signed = null) { _writer = writer; _log = log; _signed = signed; }

    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    /// <summary>
    /// A request the MVC pipeline refused BEFORE the handler ran -- a missing or invalid antiforgery token, a filter's own
    /// refusal -- still gets its one row: the handler it named, outcome refused. (A request the role framework refused is
    /// written by <see cref="AuditAuthorizationResultHandler"/>; one the handler ran for, by the page filter above.)
    /// </summary>
    public async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        var http = context.HttpContext;
        if (!http.Items.ContainsKey(typeof(AuditScope)) && IsMutating(http.Request.Method)
            && context.ActionDescriptor is Microsoft.AspNetCore.Mvc.RazorPages.CompiledPageActionDescriptor page)
        {
            var name = http.Request.Query["handler"].ToString();
            var h = page.HandlerMethods.FirstOrDefault(m => string.Equals(m.HttpMethod, http.Request.Method, StringComparison.OrdinalIgnoreCase)
                                                             && string.Equals(m.Name ?? "", name, StringComparison.OrdinalIgnoreCase));
            var (audited, action) = Plan(h?.MethodInfo, http.Request.Method);
            if (audited)
            {
                var scope = new AuditScope(action!, AuditScope.ActorOf(http.User), AuditScope.SourceOf(http.User));
                AuditTargets.Fill(scope, page.ViewEnginePath, h!.Name, null, http.Request.Query, context.RouteData.Values);
                http.Items[typeof(AuditScope)] = scope;
                var why = context.Result is Microsoft.AspNetCore.Mvc.Core.Infrastructure.IAntiforgeryValidationFailedResult
                    ? "the request's antiforgery token was missing or invalid -- nothing ran"
                    : AuditExports.MessageOf(context.Result) ?? ("refused before the handler ran (" + context.Result.GetType().Name + ")");
                await _writer.WriteAsync(scope.ToRecord(AuditOutcomes.Refused, why), CancellationToken.None);
            }
        }
        await next();
    }

    public static bool IsMutating(string method) =>
        !(HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method) || HttpMethods.IsTrace(method));

    /// What the filter does with a handler: (audited, action). Pure -- the coverage test asks the same question.
    public static (bool Audited, string? Action) Plan(MethodInfo? method, string httpMethod)
    {
        if (method is null) return (false, null);
        if (method.GetCustomAttribute<NotAuditedAttribute>() is not null) return (false, null);
        var a = method.GetCustomAttribute<AuditedAttribute>();
        if (a is not null) return (true, a.Action);
        return IsMutating(httpMethod) ? (true, Unlisted) : (false, null);
    }

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var http = context.HttpContext;
        var (audited, action) = Plan(context.HandlerMethod?.MethodInfo, http.Request.Method);
        if (!audited) { await next(); return; }

        var scope = new AuditScope(action!, AuditScope.ActorOf(http.User), AuditScope.SourceOf(http.User));
        var page = context.ActionDescriptor.ViewEnginePath;
        var handler = context.HandlerMethod?.Name;
        IFormCollection? form = null;
        try { if (http.Request.HasFormContentType) form = await http.Request.ReadFormAsync(http.RequestAborted); }
        catch (Exception ex) when (ex is InvalidDataException or IOException) { form = null; }
        AuditTargets.Fill(scope, page, handler, form, http.Request.Query, context.RouteData.Values);
        if (IsMutating(http.Request.Method))
            scope.AfterJson = AuditRedaction.Form(form?.Select(kv => new KeyValuePair<string, string[]>(kv.Key, kv.Value.ToArray()!)) ?? Enumerable.Empty<KeyValuePair<string, string[]>>(),
                form?.Files.Select(f => (f.Name, f.FileName, f.Length)));
        http.Items[typeof(AuditScope)] = scope;

        PageHandlerExecutedContext? done = null;
        using (scope.Enter())
        {
            try { done = await next(); }
            catch (Exception ex)
            {
                await WriteAsync(scope, AuditOutcomes.Error, ex.Message, page, handler, http, null);
                throw;
            }
            var (outcome, text) = OutcomeOf(scope, done);
            await WriteAsync(scope, outcome, text, page, handler, http, done.Result);
        }
    }

    private async Task WriteAsync(AuditScope scope, string outcome, string? text, string page, string? handler, HttpContext http, IActionResult? result)
    {
        if (!IsMutating(http.Request.Method))
        {
            // a GET that is audited (an export, a print, a redeemed link): what was asked for and how much was returned
            scope.Rows ??= AuditExports.CountRows(result);
            var o = new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["page"] = page, ["handler"] = handler,
                ["filter"] = scope.Filter ?? AuditExports.QueryText(http.Request.Query),
                ["rows"] = scope.Rows,
            };
            if (result is FileResult f) o["file"] = f.FileDownloadName;
            scope.AfterJson ??= JsonSerializer.Serialize(o);
        }
        // the response is already decided: the write must not cancel with the request
        await _writer.WriteAsync(scope.ToRecord(outcome, text), CancellationToken.None);
        // CR8 step 2 (observe only): a change that went through is recorded with the person's signed token for the engine to verify
        if (_signed is not null && IsMutating(http.Request.Method) && outcome == AuditOutcomes.Ok && !scope.WhatIf)
            await _signed.WriteAsync(http, scope, CancellationToken.None);
    }

    /// The outcome of a handler: the handler's own word first; then an exception, a 4xx / 5xx result, an invalid model, a
    /// red toast or the page's own Error / Why message; else ok.
    public static (string Outcome, string? Text) OutcomeOf(AuditScope scope, PageHandlerExecutedContext done)
    {
        if (scope.Outcome is { } own) return (own, scope.OutcomeText);
        if (done.Exception is { } ex && !done.ExceptionHandled) return (AuditOutcomes.Error, ex.Message);
        var result = done.Result;
        switch (result)
        {
            case ForbidResult or ChallengeResult or UnauthorizedResult: return (AuditOutcomes.Refused, "not allowed");
            case IStatusCodeActionResult { StatusCode: >= 400 } sc:
                return (sc.StatusCode >= 500 ? AuditOutcomes.Error : AuditOutcomes.Refused, AuditExports.MessageOf(result) ?? ("HTTP " + sc.StatusCode));
        }
        if (!done.ModelState.IsValid)
            return (AuditOutcomes.Refused, string.Join("; ", done.ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).Where(m => m.Length > 0).Take(5)));
        var pm = done.HandlerInstance as PageModel;
        var toast = pm?.TempData.Peek("toast") as string;
        var kind = pm?.TempData.Peek("toastKind") as string;
        if (kind == "error") return (AuditOutcomes.Refused, toast);
        if (kind == "warn" && toast is not null && toast.StartsWith("Not ", StringComparison.Ordinal)) return (AuditOutcomes.Refused, toast);
        if (result is PageResult && pm is not null)
        {
            foreach (var name in new[] { "Error", "Why" })
                if (pm.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.Instance)?.GetValue(pm) is string s && s.Length > 0)
                    return (AuditOutcomes.Refused, s);
        }
        return (AuditOutcomes.Ok, toast);
    }
}

/// The target / scope of a web request, from the request itself (the handler may set better ones).
public static class AuditTargets
{
    /// The fields that NAME the object a request acts on, in order of preference.
    public static readonly string[] KeyFields =
    [
        "id", "name", "key", "job", "principalId", "departmentId", "memberId", "advisorId", "signInId", "ruleId", "overrideId", "flowId",
        "exemptionId", "requestId", "number", "serviceNumber", "domain", "role", "kind", "person", "scope", "pack", "item", "assetKey", "findingKey", "ids",
    ];
    private static readonly string[] DomainFields = ["domain", "securityDomain", "dom"];
    private static readonly string[] DepartmentFields = ["departmentId", "department", "dept"];

    public static void Fill(AuditScope scope, string page, string? handler, IFormCollection? form, IQueryCollection query, Microsoft.AspNetCore.Routing.RouteValueDictionary route)
    {
        string? Get(string k)
        {
            foreach (var (key, val) in (IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>>?)form ?? Array.Empty<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>>())
                if (string.Equals(key, k, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(val.ToString())) return val.ToString();
            foreach (var (key, val) in query)
                if (string.Equals(key, k, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(val.ToString())) return val.ToString();
            return route.TryGetValue(k, out var r) && r is not null && k != "page" ? Convert.ToString(r, CultureInfo.InvariantCulture) : null;
        }
        var parts = new List<string>();
        foreach (var k in KeyFields)
        {
            if (parts.Count == 3) break;
            if (AuditRedaction.IsSecretField(k)) continue;
            if (Get(k) is { } v) parts.Add(k + "=" + (v.Length > 80 ? v[..80] + "..." : v));
        }
        scope.Target = page + (handler is null ? "" : "?handler=" + handler) + (parts.Count == 0 ? "" : "|" + string.Join(", ", parts));
        foreach (var k in DomainFields)
            if (Get(k) is { } d && SecurityDomains.IsWellFormed(d.Trim())) { scope.Domain ??= d.Trim(); break; }
        foreach (var k in DepartmentFields)
            if (Get(k) is { } d && int.TryParse(d, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0) { scope.DepartmentId ??= n; break; }
        // the department pages name their department as ?id=
        if (scope.DepartmentId is null && page.Contains("/Departments/", StringComparison.OrdinalIgnoreCase) && !page.Contains("/Rules", StringComparison.OrdinalIgnoreCase)
            && !page.Contains("/Flows", StringComparison.OrdinalIgnoreCase) && Get("id") is { } id && int.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var did) && did > 0)
            scope.DepartmentId = did;
    }
}

/// Exports: the row count and the filter of what left the app.
public static partial class AuditExports
{
    /// The rows of a CSV answer (records after the header, quote-aware); null when the answer is not a counted file.
    public static long? CountRows(IActionResult? result)
    {
        if (result is not FileContentResult f || !f.ContentType.StartsWith("text/csv", StringComparison.OrdinalIgnoreCase)) return null;
        long records = 0; var inQuotes = false; var any = false;
        foreach (var b in f.FileContents)
        {
            if (b == (byte)'"') inQuotes = !inQuotes;
            else if (b == (byte)'\n' && !inQuotes) { records++; any = false; continue; }
            if (b != (byte)'\r') any = true;
        }
        if (any) records++;
        return Math.Max(0, records - 1);
    }

    /// The query string without the handler name and the antiforgery token -- what the export was filtered by.
    public static string? QueryText(IQueryCollection q)
    {
        var parts = q.Where(kv => !string.Equals(kv.Key, "handler", StringComparison.OrdinalIgnoreCase) && !AuditRedaction.IsSecretField(kv.Key))
            .OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => kv.Key + "=" + kv.Value.ToString()).ToList();
        var s = string.Join("&", parts);
        return s.Length == 0 ? null : AuditRedaction.Text(s.Length > 2000 ? s[..2000] : s);
    }

    [GeneratedRegex("data-access-refused>([^<]*)<", RegexOptions.CultureInvariant)]
    private static partial Regex Refused();

    /// The message a refusal carried (the role framework's page, a BadRequest / NotFound text, a JSON message).
    public static string? MessageOf(IActionResult? r) => r switch
    {
        ContentResult c when c.Content is { } html && Refused().Match(html) is { Success: true } m => WebUtility.HtmlDecode(m.Groups[1].Value),
        ContentResult c => c.Content is { Length: > 0 and < 400 } t && !t.Contains('<') ? t : null,
        ObjectResult { Value: string s } => s,
        JsonResult j => j.Value?.GetType().GetProperty("message")?.GetValue(j.Value) as string,
        _ => null,
    };
}

/// <summary>
/// A request the role framework refused BEFORE any handler ran (the folder / page policies): one 'event' row
/// <c>web.request.refused</c> -- a Reader opening an Admin page, a no-role account, a POST to a page above one's role.
/// The default handler then answers exactly as before.
/// </summary>
public sealed class AuditAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _default = new();
    private readonly IAuditWriter _writer;
    public AuditAuthorizationResultHandler(IAuditWriter writer) => _writer = writer;

    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Forbidden)
        {
            var why = authorizeResult.AuthorizationFailure?.FailureReasons.Select(r => r.Message).FirstOrDefault(m => m.Length > 0)
                      ?? "the role framework refused the request";
            var scope = new AuditScope("web.request.refused", AuditScope.ActorOf(context.User), AuditScope.SourceOf(context.User))
            {
                Target = context.Request.Path.Value + (context.Request.Query.TryGetValue("handler", out var h) ? "?handler=" + h : ""),
                AfterJson = JsonSerializer.Serialize(new { method = context.Request.Method, role = AccessClaims.Label(context.User.EffectiveRole()) }),
            };
            await _writer.WriteAsync(scope.ToRecord(AuditOutcomes.Refused, why), CancellationToken.None);
        }
        await _default.HandleAsync(next, context, policy, authorizeResult);
    }
}
