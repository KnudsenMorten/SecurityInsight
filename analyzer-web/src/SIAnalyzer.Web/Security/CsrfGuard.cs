namespace SIAnalyzer.Web.Security;

/// <summary>
/// AUDIT #14 - cross-site request forgery on the state-changing endpoints.
///
/// WHY THE OBVIOUS ANSWERS ARE WRONG HERE:
///
///  * <b>The default-deny auth gate (#3) does NOT absorb this.</b> Easy Auth sits in FRONT of the
///    container. A victim who is signed in carries the platform session cookie, so a cross-site form
///    POST is authenticated BY THE PLATFORM and arrives with a valid <c>X-MS-CLIENT-PRINCIPAL</c>.
///    The gate then passes it. Authentication is not the control CSRF needs.
///  * <b><c>form-action 'self'</c> (#13) does not help either.</b> That directive constrains where
///    OUR pages may submit; the attacker's page carries its own policy.
///  * <b>Antiforgery TOKENS are the wrong tool in this deployment.</b> They are signed with the
///    DataProtection key ring, which is ephemeral in this container - no persisted keys, no shared
///    storage. Tokens would break across replicas and across every restart. So the guard here is
///    deliberately STATELESS: it needs no key, no session and no shared state.
///
/// The rules, in order. Each is a fact the browser controls and the attacker's page cannot forge:
///  1. Safe methods pass untouched.
///  2. <c>Origin</c>, if present, must match this request's own origin. A cross-site form POST sends
///     one, and script on the attacker's page cannot change it.
///  3. <c>Sec-Fetch-Site</c>, if present, must be <c>same-origin</c> or <c>none</c>.
///  4. With NO browser signals at all (a non-browser client, e.g. an MCP agent or curl), require a
///     non-simple content type or an explicit header. An HTML form can only ever send
///     <c>application/x-www-form-urlencoded</c>, <c>multipart/form-data</c> or <c>text/plain</c>, and
///     cannot add headers, so this is the boundary a form cannot cross.
///
/// ⚠️ Rule 2 depends on <c>UseForwardedHeaders</c> (audit #13) running first. Behind TLS-terminating
/// ingress the browser sends <c>Origin: https://…</c>; without forwarded headers
/// <c>Request.Scheme</c> is "http" and EVERY same-origin POST would be rejected. The two fixes are
/// coupled - hence <see cref="SecurityHeadersTests"/> and this guard's tests both pin it.
/// </summary>
public static class CsrfGuard
{
    /// <summary>Opt-out header for a non-browser caller that sends no content type (rule 4).</summary>
    public const string RequestHeader = "X-SIA-Request";

    private static bool IsUnsafe(string method) =>
        HttpMethods.IsPost(method) || HttpMethods.IsPut(method) ||
        HttpMethods.IsPatch(method) || HttpMethods.IsDelete(method);

    /// <summary>True when the body type is one an HTML form could have produced.</summary>
    private static bool IsFormSubmittableContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return true;   // no body: a form can do that too
        var t = contentType.Split(';')[0].Trim();
        return t.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
            || t.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase)
            || t.Equals("text/plain", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The decision, split out so it can be tested without a server.</summary>
    public static bool IsAllowed(HttpRequest req, out string reason)
    {
        reason = "";
        if (!IsUnsafe(req.Method)) { reason = "safe method"; return true; }

        var origin = req.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origin))
        {
            // "null" is the opaque origin a sandboxed frame sends - never ours.
            var self = $"{req.Scheme}://{req.Host.Value}";
            if (!string.Equals(origin, self, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"Origin '{origin}' does not match '{self}'";
                return false;
            }
            reason = "same origin";
            return true;
        }

        var site = req.Headers["Sec-Fetch-Site"].ToString();
        if (!string.IsNullOrEmpty(site))
        {
            if (site.Equals("same-origin", StringComparison.OrdinalIgnoreCase) ||
                site.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                reason = $"Sec-Fetch-Site: {site}";
                return true;
            }
            reason = $"Sec-Fetch-Site: {site}";
            return false;
        }

        // No browser signals: not a browser, or one too old to send them.
        if (req.Headers.ContainsKey(RequestHeader)) { reason = "explicit " + RequestHeader; return true; }
        if (!IsFormSubmittableContentType(req.ContentType))
        {
            reason = $"non-form content type '{req.ContentType}'";
            return true;
        }

        reason = $"no Origin, no Sec-Fetch-Site, and a form-submittable content type '{req.ContentType ?? "(none)"}'";
        return false;
    }

    /// <summary>Register AFTER UseForwardedHeaders (see the remarks) and before the endpoints.</summary>
    public static IApplicationBuilder UseSIAnalyzerCsrfGuard(this IApplicationBuilder app) =>
        app.Use(async (ctx, next) =>
        {
            if (!IsAllowed(ctx.Request, out var reason))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsJsonAsync(new
                {
                    error = "Cross-site request rejected. State-changing requests must come from the SecurityInsight Analyzer itself.",
                    detail = reason,
                });
                return;
            }
            await next();
        });
}
