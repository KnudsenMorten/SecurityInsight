namespace SigninFront;

/// <summary>
/// The security headers on EVERY response the front sends -- its own (401, redirects, /healthz, /signout) and every
/// forwarded one. Fixed values, no per-product override (owner 2026-10-18: web-app security identical in every product).
/// An upstream value for the same header is REPLACED, never merged. README "Security headers" prints these verbatim and a
/// test keeps the two equal.
/// </summary>
public static class SecurityHeaders
{
    public const string ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
        "font-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    public const string StrictTransportSecurity = "max-age=31536000";
    public const string XFrameOptions = "DENY";
    public const string XContentTypeOptions = "nosniff";
    public const string ReferrerPolicy = "same-origin";

    public static readonly IReadOnlyList<KeyValuePair<string, string>> All = new[]
    {
        new KeyValuePair<string, string>("Content-Security-Policy", ContentSecurityPolicy),
        new KeyValuePair<string, string>("Strict-Transport-Security", StrictTransportSecurity),
        new KeyValuePair<string, string>("X-Frame-Options", XFrameOptions),
        new KeyValuePair<string, string>("X-Content-Type-Options", XContentTypeOptions),
        new KeyValuePair<string, string>("Referrer-Policy", ReferrerPolicy),
    };

    public static void Apply(IHeaderDictionary headers)
    {
        foreach (var kv in All) headers[kv.Key] = kv.Value;
        headers.Remove("Server");
        headers.Remove("X-Powered-By");
    }
}

public static class FrontVersion
{
    /// <summary>Must equal FRAMEWORK/signin-front/VERSION (a test checks). Sent upstream as X-Signin-Front.</summary>
    public const string Value = "1.4.5";
}
