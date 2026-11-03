using System.Net;
using System.Net.Http.Headers;
using Yarp.ReverseProxy.Forwarder;

namespace SigninFront;

/// <summary>
/// The upstream request contract (README "Upstream contract"): every inbound identity header is removed, then exactly
/// ONE identity is set -- Authorization: Bearer &lt;JWT&gt; -- plus X-Forwarded-Proto / -Host / -For and X-Signin-Front.
/// </summary>
public static class UpstreamHeaders
{
    private static readonly string[] StrippedPrefixes =
    {
        "X-MS-CLIENT-PRINCIPAL", "X-MS-TOKEN-", "X-Forwarded-User", "X-Signin-", "X-Forwarded-", "X-Original-",
    };

    public static bool IsStripped(string name)
    {
        if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var p in StrippedPrefixes) if (name.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// The cookies the FRONT itself writes -- and only those (1.1.0): the session cookie __Host-signin and its chunks
    /// __Host-signinC1, C2 ...; the OIDC nonce .AspNetCore.OpenIdConnect.Nonce.*; the OIDC correlation .AspNetCore.Correlation.*.
    /// They never reach the app, and an app may never set them. Every other cookie -- the app's own, including the app's
    /// own ASP.NET ones such as .AspNetCore.Antiforgery.* -- passes both ways unchanged. (1.0.x stripped every
    /// ".AspNetCore.*" cookie, which broke an app's antiforgery form posts.)
    /// </summary>
    public static bool IsFrontCookie(string cookieName)
    {
        var n = (cookieName ?? "").Trim();
        if (n.Equals(FrontCookie.Name, StringComparison.OrdinalIgnoreCase)) return true;
        if (n.Equals(SigninFailure.RetryCookie, StringComparison.OrdinalIgnoreCase)) return true;   // 1.2.0 retry marker
        if (n.Length > FrontCookie.Name.Length + 1 && n.StartsWith(FrontCookie.Name + "C", StringComparison.OrdinalIgnoreCase) &&
            n.Substring(FrontCookie.Name.Length + 1).All(char.IsDigit)) return true;
        return n.StartsWith(".AspNetCore.OpenIdConnect.Nonce.", StringComparison.OrdinalIgnoreCase) ||
               n.StartsWith(".AspNetCore.Correlation.", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The cookie name of a Set-Cookie value ("name=value; attrs").</summary>
    public static string SetCookieName(string setCookie)
    {
        var s = setCookie ?? "";
        var eq = s.IndexOf('=');
        var semi = s.IndexOf(';');
        var end = eq < 0 ? (semi < 0 ? s.Length : semi) : eq;
        return s.Substring(0, end).Trim();
    }

    /// <summary>
    /// The Set-Cookie list the browser gets: the front's OWN Set-Cookie values written before forwarding (a session refresh),
    /// then every upstream one EXCEPT those whose name is a front cookie -- an app may never overwrite the front's session.
    /// </summary>
    public static string[] MergeSetCookies(IEnumerable<string> frontOwn, IEnumerable<string> upstream) =>
        frontOwn.Concat(upstream.Where(v => !IsFrontCookie(SetCookieName(v)))).ToArray();

    public static string FilterCookieHeader(string cookieHeader)
    {
        var kept = new List<string>();
        foreach (var part in cookieHeader.Split(';'))
        {
            var p = part.Trim();
            if (p.Length == 0) continue;
            var eq = p.IndexOf('=');
            var name = eq < 0 ? p : p.Substring(0, eq);
            if (!IsFrontCookie(name.Trim())) kept.Add(p);
        }
        return string.Join("; ", kept);
    }

    public static void Apply(HttpContext ctx, HttpRequestMessage req, string? jwt)
    {
        foreach (var name in req.Headers.Select(h => h.Key).ToList())
            if (IsStripped(name)) req.Headers.Remove(name);
        if (req.Content is not null)
            foreach (var name in req.Content.Headers.Select(h => h.Key).ToList())
                if (IsStripped(name)) req.Content.Headers.Remove(name);

        if (req.Headers.TryGetValues("Cookie", out var cookies))
        {
            var filtered = FilterCookieHeader(string.Join("; ", cookies));
            req.Headers.Remove("Cookie");
            if (filtered.Length > 0) req.Headers.TryAddWithoutValidation("Cookie", filtered);
        }

        if (!string.IsNullOrEmpty(jwt)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        req.Headers.TryAddWithoutValidation("X-Forwarded-Proto", ctx.Request.Scheme);
        if (ctx.Request.Host.HasValue) req.Headers.TryAddWithoutValidation("X-Forwarded-Host", ctx.Request.Host.Value);
        var ip = ctx.Connection.RemoteIpAddress;
        if (ip is not null) req.Headers.TryAddWithoutValidation("X-Forwarded-For", ip.ToString());
        req.Headers.TryAddWithoutValidation("X-Signin-Front", FrontVersion.Value);
    }
}

public sealed class FrontTransformer : HttpTransformer
{
    private readonly string? _jwt;
    public FrontTransformer(string? jwt) { _jwt = jwt; }

    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix, CancellationToken cancellationToken)
    {
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);
        // 1.2.1: YARP's base transformer copies the ORIGINAL Host (the public name). An app bound to the loopback address
        // only (PIM: an HttpListener on http://127.0.0.1:<port>/) then answers its own "no matching prefix" 404 and no app
        // code runs (owner's CR7 test, 2026-10-20). Host = the upstream address; the public host travels in X-Forwarded-Host.
        proxyRequest.Headers.Host = null;
        UpstreamHeaders.Apply(httpContext, proxyRequest, _jwt);
    }

    public override async ValueTask<bool> TransformResponseAsync(HttpContext httpContext, HttpResponseMessage? proxyResponse, CancellationToken cancellationToken)
    {
        // What the FRONT already set on this response (a refreshed session) -- kept; then the upstream's, minus collisions.
        var frontOwn = httpContext.Response.Headers.SetCookie.Where(v => v is not null).Select(v => v!).ToArray();
        var result = await base.TransformResponseAsync(httpContext, proxyResponse, cancellationToken);
        var upstream = new List<string>();
        if (proxyResponse is not null && proxyResponse.Headers.TryGetValues("Set-Cookie", out var vals)) upstream.AddRange(vals);
        var merged = UpstreamHeaders.MergeSetCookies(frontOwn, upstream);
        httpContext.Response.Headers.Remove("Set-Cookie");
        if (merged.Length > 0) httpContext.Response.Headers.SetCookie = merged;
        return result;
    }
}

/// <summary>The one HTTP client to the app container. A class of its own so tests can put a fake app behind it.</summary>
public sealed class UpstreamClient
{
    public HttpMessageInvoker Invoker { get; }
    public UpstreamClient(HttpMessageInvoker invoker) { Invoker = invoker; }

    public static HttpMessageInvoker CreateDefaultInvoker() => new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.None,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(15),
    });

    public static readonly ForwarderRequestConfig RequestConfig = new()
    {
        ActivityTimeout = TimeSpan.FromMinutes(10),
        Version = HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
    };
}

public static class FrontCookie
{
    /// <summary>__Host- prefix: Secure, Path=/, no Domain -- enforced by the browser.</summary>
    public const string Name = "__Host-signin";
}
