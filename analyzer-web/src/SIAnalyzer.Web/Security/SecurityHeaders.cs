using System.Security.Cryptography;

namespace SIAnalyzer.Web.Security;

/// <summary>
/// AUDIT #13 - response security headers, including a NONCE-based Content-Security-Policy.
///
/// Why a nonce and not <c>'unsafe-inline'</c>: SIA renders every page server-side and ships four
/// inline &lt;script&gt; blocks. A policy of <c>script-src 'self' 'unsafe-inline'</c> would have been a
/// one-line change that still permits injected script to run - the exact thing a CSP is for. So the
/// inline blocks carry a per-request nonce and the twelve inline <c>on*</c> handlers the app used to
/// carry were removed (audit #19 closed with them): <b>a nonce does not whitelist inline event
/// handlers</b>, only <c>'unsafe-inline'</c> does, so keeping one handler would have forced the weak
/// policy for the whole app.
///
/// <c>style-src</c> deliberately keeps <c>'unsafe-inline'</c>: the pages use <c>style=</c> ATTRIBUTES,
/// which no nonce can cover. Tightening that means moving every inline style into a served stylesheet
/// - real work, no XSS win worth the churn while script-src is strict.
/// </summary>
public static class SecurityHeaders
{
    private const string NonceItemKey = "SIAnalyzer.CspNonce";

    /// <summary>
    /// The per-request CSP nonce, or <c>null</c> outside a request (or when this middleware has not
    /// run). Renderers that emit an inline script MUST pass it; a null nonce renders a plain
    /// &lt;script&gt; tag, which is correct for STANDALONE artifacts (an emailed or downloaded HTML
    /// file is not served by us and carries no CSP).
    /// </summary>
    public static string? GetCspNonce(this HttpContext ctx) =>
        ctx.Items.TryGetValue(NonceItemKey, out var v) ? v as string : null;

    /// <summary>Emits the security headers and mints the per-request nonce. Register EARLY so the
    /// headers are present on every response, including the 401 from the default-deny auth gate.</summary>
    public static IApplicationBuilder UseSIAnalyzerSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (ctx, next) =>
        {
            // 128 bits of CSPRNG per request. A nonce must be unguessable and MUST NOT be reused
            // across responses -- a predictable or static nonce is the same as 'unsafe-inline'.
            // (GetBytes rather than a stackalloc Span: this is an async method, where C# 12 forbids
            // ref-struct locals.)
            //
            // HEX, not base64, and this is not cosmetic: base64 emits '+' and '/', which every HTML
            // encoder on the way out turns into character references (nonce="a&#x2B;b"). Browsers
            // decode those before matching, so it WORKS -- but the attribute no longer equals the
            // header byte-for-byte, so any check comparing the two passes or fails depending on
            // which characters the random value happened to contain. A flaky test guarding a CSP is
            // worse than none. Hex is in the CSP base64-value grammar and survives HTML encoding
            // untouched.
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            ctx.Items[NonceItemKey] = nonce;

            var h = ctx.Response.Headers;
            h["Content-Security-Policy"] =
                "default-src 'self'; " +
                $"script-src 'self' 'nonce-{nonce}'; " +
                "style-src 'self' 'unsafe-inline'; " +   // style= attributes; see the class remarks
                "img-src 'self' data:; " +
                "font-src 'self'; " +
                "connect-src 'self'; " +
                "object-src 'none'; " +
                "base-uri 'self'; " +
                "form-action 'self'; " +
                "frame-ancestors 'none'";

            h["X-Content-Type-Options"] = "nosniff";
            h["Referrer-Policy"] = "no-referrer";
            // frame-ancestors above is the modern control; X-Frame-Options is kept for older agents.
            h["X-Frame-Options"] = "DENY";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()";

            await next();
        });
}
