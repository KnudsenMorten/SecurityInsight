using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace SigninFront;

/// <summary>
/// 1.2.0 -- a sign-in that comes back FAILED never hangs and never shows a 500. Every remote failure -- an error answer on
/// the callback (interaction_required, login_required, consent_required, a session ended by Conditional Access sign-in
/// frequency such as AADSTS50058 / AADSTS70044), a failed code redemption (invalid_grant, AADSTS70044), a correlation or
/// nonce cookie a proxy dropped, an unreadable state -- gets ONE fresh interactive sign-in (prompt=login). A second failure
/// in the same browser session ends on a short page that names the Entra code (AADSTS...) and offers "Sign in again":
/// never a loop. The marker is the state's own item AND a small cookie (the state is unreadable in some failures).
/// </summary>
public static class SigninFailure
{
    public const string RetryItem = "signin.retry";
    public const string RetryCookie = "__Host-signin-retry";
    public static readonly TimeSpan RetryWindow = TimeSpan.FromMinutes(15);

    private static readonly Regex AadCode = new(@"\bAADSTS\d{4,7}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly string[] KnownErrors =
    {
        "interaction_required", "login_required", "consent_required", "invalid_grant", "access_denied", "temporarily_unavailable",
    };

    public enum Action { Retry, ErrorPage }

    public sealed record Decision(Action Action, string? AadstsCode, string? ErrorWord, string Kind);

    /// <summary>PURE. What to do with one failed sign-in: retry once, else the error page. Never reads a token or a value.</summary>
    public static Decision Decide(Exception? failure, bool alreadyRetried)
    {
        var text = MessagesOf(failure);
        var code = AadCode.Match(text) is { Success: true } m ? m.Value : null;
        var word = KnownErrors.FirstOrDefault(w => text.Contains(w, StringComparison.OrdinalIgnoreCase));
        var kind = Kind(text, code, word);
        return new Decision(alreadyRetried ? Action.ErrorPage : Action.Retry, code, word, kind);
    }

    private static string Kind(string text, string? code, string? word)
    {
        if (code is "AADSTS50058" or "AADSTS70044" or "AADSTS700082" or "AADSTS50132" or "AADSTS50133" || word is "interaction_required" or "login_required")
            return "the sign-in has to be repeated (your organisation's sign-in policy ended the earlier session)";
        if (word is "invalid_grant") return "the sign-in code could not be redeemed";
        if (word is "consent_required") return "the app is missing an administrator's approval";
        if (word is "access_denied") return "the sign-in was refused";
        if (text.Contains("Correlation failed", StringComparison.OrdinalIgnoreCase) || text.Contains("nonce", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("message.State", StringComparison.OrdinalIgnoreCase))
            return "the browser did not bring back the sign-in's own cookie (often a proxy or a privacy setting)";
        return "the sign-in could not be completed";
    }

    private static string MessagesOf(Exception? e)
    {
        var parts = new List<string>();
        for (var x = e; x is not null && parts.Count < 6; x = x.InnerException) parts.Add(x.Message ?? "");
        return string.Join(" | ", parts);
    }

    public static bool AlreadyRetried(RemoteFailureContext ctx) =>
        (ctx.Properties?.Items.TryGetValue(RetryItem, out var v) == true && v == "1") || ctx.Request.Cookies.ContainsKey(RetryCookie);

    /// <summary>The OnRemoteFailure handler: one fresh sign-in, else the readable page. The response is always handled.</summary>
    public static async Task HandleAsync(RemoteFailureContext ctx, ILogger log)
    {
        var d = Decide(ctx.Failure, AlreadyRetried(ctx));
        // never the exception text (it can carry claims) -- the code and the kind are enough to diagnose
        log.LogWarning("signin-front: sign-in failed ({Type}; {Code}; {Word}) -> {Action}", ctx.Failure?.GetType().Name ?? "none", d.AadstsCode ?? "no AADSTS code", d.ErrorWord ?? "-", d.Action);
        ctx.HandleResponse();
        if (d.Action == Action.Retry)
        {
            ctx.Response.Cookies.Append(RetryCookie, "1", new CookieOptions
            {
                // the callback is a cross-site POST from the sign-in page: only SameSite=None comes back on it
                HttpOnly = true, Secure = true, SameSite = SameSiteMode.None, Path = "/", MaxAge = RetryWindow, IsEssential = true,
            });
            var back = ctx.Properties?.RedirectUri is { Length: > 0 } ru && ru.StartsWith('/') && !ru.StartsWith("//") ? ru : "/";
            var props = new OpenIdConnectChallengeProperties { RedirectUri = back, Prompt = "login" };
            props.Items[RetryItem] = "1";
            await ctx.HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, props);
            return;
        }
        ctx.Response.Cookies.Delete(RetryCookie, new CookieOptions { Secure = true, SameSite = SameSiteMode.None, Path = "/" });
        await WriteErrorPageAsync(ctx.Response, d);
    }

    public static async Task WriteErrorPageAsync(HttpResponse r, Decision d)
    {
        r.StatusCode = StatusCodes.Status400BadRequest;
        r.ContentType = "text/html; charset=utf-8";
        r.Headers.CacheControl = "no-store";
        var code = d.AadstsCode is null ? "" : $"<p>Microsoft Entra code: <code>{WebUtility.HtmlEncode(d.AadstsCode)}</code></p>";
        await r.WriteAsync("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign-in not completed</title></head><body>" +
            "<h1>Sign-in could not be completed</h1>" +
            $"<p>{WebUtility.HtmlEncode(char.ToUpperInvariant(d.Kind[0]) + d.Kind.Substring(1))}.</p>{code}" +
            "<p><a href=\"/\">Sign in again</a></p>" +
            "<p>If this repeats, give your administrator the time and the code above.</p></body></html>");
    }
}

/// <summary>
/// The request's cookies kept small, so the sign-in works behind ANY proxy (framework §12.11g item 9: the worst-case Cookie
/// header stays under 4 KB; a corporate proxy commonly refuses 8 KB, Container Apps' Envoy drops ~64 KB).
/// - 1.2.0: one WARNING line when a request's Cookie header is over 8 KB (the size, never a value); the chunk cookies of a
///   1.1.0 session are removed.
/// - 1.3.0: every challenge deletes the earlier sign-ins' correlation / nonce pairs (FrontAuth) and a pair lives 15 minutes,
///   so a browser carries at most ONE pending sign-in. Belt and braces: more than one pair is deleted on ANY request that
///   carries them, the callback included (its own handler has read them already; a second tab's sign-in, if any, is
///   retried once). Every Easy Auth leftover (AppServiceAuth*) is deleted: an app that moved from built-in authentication
///   brings them along.
/// - 1.3.0: a Cookie header over 16 KB is answered by the front itself with the clear-and-retry page -- every cookie it can
///   see is deleted and the browser is sent back to start -- so a browser stuck with old cookies heals itself, never a 431.
/// </summary>
public static class CookieHygiene
{
    public const int WarnBytes = 8 * 1024;
    public const int ClearBytes = 16 * 1024;
    /// <summary>Cookie NAMES (a sign-in's nonce + correlation = 2): one pending sign-in is kept, more are deleted.</summary>
    public const int MaxPendingSignins = 2;
    /// <summary>At most this many Set-Cookie deletions in one response (a response header has its own size limits).</summary>
    public const int MaxDeletesPerResponse = 40;
    public static readonly string[] Paths = { "/", "/signin-oidc" };

    public static bool IsLegacyChunk(string name) =>
        name.Length > FrontCookie.Name.Length + 1 && name.StartsWith(FrontCookie.Name + "C", StringComparison.OrdinalIgnoreCase) &&
        name.Substring(FrontCookie.Name.Length + 1).All(char.IsDigit);

    public static bool IsPendingSignin(string name) =>
        name.StartsWith(".AspNetCore.OpenIdConnect.Nonce.", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith(".AspNetCore.Correlation.", StringComparison.OrdinalIgnoreCase);

    /// <summary>Container Apps / App Service built-in authentication (Easy Auth) cookies: AppServiceAuthSession, its chunks, ...</summary>
    public static bool IsEasyAuthLeftover(string name) => name.StartsWith("AppServiceAuth", StringComparison.OrdinalIgnoreCase);

    /// <summary>PURE. The cookie names to delete on this request (the callback's own pair is never needed after its request).</summary>
    public static IReadOnlyList<string> ToDelete(IEnumerable<string> names, bool isCallback)
    {
        var all = names.ToList();
        var del = new List<string>();
        var chunks = all.Where(IsLegacyChunk).ToList();
        if (chunks.Count > 0) { del.AddRange(chunks); if (all.Contains(FrontCookie.Name, StringComparer.OrdinalIgnoreCase)) del.Add(FrontCookie.Name); }
        var pending = all.Where(IsPendingSignin).ToList();
        if (pending.Count > MaxPendingSignins) del.AddRange(pending);
        del.AddRange(all.Where(IsEasyAuthLeftover));
        return del.Distinct(StringComparer.Ordinal).Take(MaxDeletesPerResponse).ToList();
    }

    /// <summary>Deletes one cookie on both paths a front cookie can have been written with.</summary>
    public static void Delete(HttpResponse r, string name)
    {
        foreach (var p in Paths)
            r.Cookies.Delete(name, new CookieOptions { Path = p, Secure = true, SameSite = IsPendingSignin(name) ? SameSiteMode.None : SameSiteMode.Lax });
    }

    public static async Task InvokeAsync(HttpContext ctx, Func<Task> next, ILogger log)
    {
        var header = ctx.Request.Headers.Cookie.ToString();
        if (header.Length > WarnBytes)
            log.LogWarning("signin-front: the request's Cookie header is {Bytes} bytes (over 8 KB) on {Path} -- a proxy may refuse requests this large", header.Length, ctx.Request.Path.Value);
        if (header.Length > ClearBytes)
        {
            await WriteClearPageAsync(ctx, log, header.Length);
            return;
        }
        var isCallback = ctx.Request.Path.StartsWithSegments("/signin-oidc") || ctx.Request.Path.StartsWithSegments("/signout-callback-oidc");
        foreach (var n in ToDelete(ctx.Request.Cookies.Keys, isCallback)) Delete(ctx.Response, n);
        await next();
    }

    /// <summary>
    /// The clear-and-retry answer: EVERY cookie the request carries is deleted (the front's, a sign-in's, Easy Auth's and the
    /// app's own -- a browser this far gone cannot be sorted out cookie by cookie), then a navigation goes back to "/" (a new
    /// sign-in); a script call gets 401 so the page reloads itself. No value is ever logged or echoed.
    /// </summary>
    public static async Task WriteClearPageAsync(HttpContext ctx, ILogger log, int bytes)
    {
        var names = ctx.Request.Cookies.Keys.ToList();
        log.LogWarning("signin-front: Cookie header {Bytes} bytes on {Path} -- over {Limit}: {Count} cookies cleared, the browser starts again", bytes, ctx.Request.Path.Value, ClearBytes, names.Count);
        foreach (var n in names.Take(MaxDeletesPerResponse)) Delete(ctx.Response, n);
        ctx.Response.Headers.CacheControl = "no-store";
        if (!Navigation.IsNavigation(ctx.Request))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }
        ctx.Response.StatusCode = StatusCodes.Status200OK;
        ctx.Response.ContentType = "text/html; charset=utf-8";
        // a meta refresh (no script: CSP script-src 'self'); more than MaxDeletesPerResponse cookies take one more round
        await ctx.Response.WriteAsync("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"1;url=/\">" +
            "<title>Starting the sign-in again</title></head><body><h1>Starting the sign-in again</h1>" +
            "<p>Old sign-in data in this browser was cleared. If nothing happens, <a href=\"/\">continue</a>.</p></body></html>");
    }
}
