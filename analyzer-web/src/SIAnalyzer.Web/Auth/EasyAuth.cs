using Microsoft.AspNetCore.Http;

namespace SIAnalyzer.Web.Auth;

/// <summary>
/// End-to-end validation of the Easy Auth client principal + the gate that keeps the
/// <c>/mcp</c> tool surface (and the gated API) behind the SAME authenticated principal as
/// the UI. The platform's Entra Easy Auth terminates sign-in in front of the container and
/// injects <c>X-MS-CLIENT-PRINCIPAL</c>; this class parses + trusts that header and, when
/// <see cref="EasyAuthOptions.RequireClientPrincipal"/> is on, rejects anonymous calls to
/// the gated endpoints (defense-in-depth, so the MCP surface is never anonymous even if the
/// platform gate is misconfigured/bypassed).
/// </summary>
public static class EasyAuth
{
    /// <summary>Parse the authenticated principal from this request's Easy Auth header,
    /// or null when the request carries no valid principal (anonymous).</summary>
    public static ClientPrincipal? GetPrincipal(HttpContext http) =>
        ClientPrincipal.FromHeaderValue(http.Request.Headers[ClientPrincipal.HeaderName]);

    /// <summary>True when this request carries a valid, authenticated Easy Auth principal.</summary>
    public static bool IsAuthenticated(HttpContext http) => GetPrincipal(http) is not null;

    /// <summary>
    /// Enforce the gate on a sensitive endpoint (e.g. <c>/mcp</c>). When the gate is ON and
    /// the request is anonymous, returns a 401 result and the caller short-circuits; when
    /// the gate is OFF, or the request is authenticated, returns null (allow). This is the
    /// allow/deny decision the Phase-3 tests exercise.
    /// </summary>
    public static IResult? RequireAuthenticated(HttpContext http, EasyAuthOptions opts)
    {
        if (!opts.RequireClientPrincipal) return null;            // gate off => allow (demo/local/test default)
        if (IsAuthenticated(http)) return null;                   // authenticated => allow
        return Results.Json(
            new { error = "Unauthenticated. This endpoint requires an Entra-authenticated principal (Easy Auth)." },
            statusCode: StatusCodes.Status401Unauthorized);
    }
}
