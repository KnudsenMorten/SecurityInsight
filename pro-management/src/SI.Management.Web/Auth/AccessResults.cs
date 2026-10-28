using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace SI.Management.Web.Auth;

/// <summary>
/// The answer to a refused change: HTTP 403 with the reason, and nothing written. A JSON caller (the tier board's drop)
/// gets <c>{ ok: false, message }</c>; a form post gets a short page with the reason and a way back.
/// </summary>
public static class AccessResults
{
    public static IActionResult Refused(HttpRequest request, AccessDecision decision)
    {
        var message = "Not allowed: " + decision.Reason + " Nothing was written.";
        if (request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase))
            return new JsonResult(new { ok = false, message }) { StatusCode = StatusCodes.Status403Forbidden };
        var back = request.Headers.Referer.ToString();
        var link = Uri.TryCreate(back, UriKind.Absolute, out var u) && u.Host == request.Host.Host ? u.PathAndQuery : "/";
        var html = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" /><title>Not allowed - SecurityInsight Pro</title>"
                 + "<link rel=\"stylesheet\" href=\"/css/site.css\" /></head><body><main id=\"main\"><h1>Not allowed</h1>"
                 + $"<div class=\"notice warn\" role=\"alert\" data-access-refused>{WebUtility.HtmlEncode(message)}</div>"
                 + $"<p><a href=\"{WebUtility.HtmlEncode(link)}\">Back</a></p></main></body></html>";
        return new ContentResult { StatusCode = StatusCodes.Status403Forbidden, ContentType = "text/html; charset=utf-8", Content = html };
    }
}
