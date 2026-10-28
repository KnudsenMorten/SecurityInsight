using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SI.Management.Web.Audit;

/// CR8 step 2, OBSERVE ONLY (framework DOCS/REQUIREMENTS.md 12.11f item 2, SI #659): every change a person makes here is
/// recorded in cfg.SignedRequest with the person's signed Entra token AS THE WEB APP RECEIVED IT and the time it was
/// captured; the pipeline runner verifies it (engine\_shared\SI-SignedRequests.ps1) and records what it WOULD refuse.
/// Nothing is refused yet, and the sign-in itself is not changed here:
///   bearer   the token the shared sign-in front forwards (Authorization: Bearer, framework 12.11g);
///   session  the ID token kept with the sign-in session, when the sign-in keeps it;
///   none     neither -- recorded too, so the runner can say how many changes it would refuse today.
/// A failed write never changes the response (logged).
public interface ISignedRequestWriter
{
    Task WriteAsync(HttpContext http, AuditScope scope, CancellationToken ct);
}

public sealed class SqlSignedRequestWriter : ISignedRequestWriter
{
    public const string InsertSql = """
INSERT INTO cfg.SignedRequest (CorrelationId, Action, Actor, TokenSource, Token, Audience) VALUES (@Cid, @Action, @Actor, @Source, @Token, @Aud);
""";

    private readonly SI.Management.Web.Data.ISqlExecutor _sql;
    private readonly ILogger<SqlSignedRequestWriter> _log;
    private readonly string _audience;

    public SqlSignedRequestWriter(SI.Management.Web.Data.ISqlExecutor sql, ILogger<SqlSignedRequestWriter> log, IConfiguration config)
    {
        _sql = sql; _log = log; _audience = config["AzureAd:ClientId"] ?? "";
    }

    /// PURE. The bearer token of an Authorization header, or null.
    public static string? BearerOf(string? header) =>
        header is { Length: > 7 } h && h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) && h[7..].Trim() is { Length: > 0 } t && t.Count(c => c == '.') == 2 ? t : null;

    public async Task WriteAsync(HttpContext http, AuditScope scope, CancellationToken ct)
    {
        try
        {
            var (source, token) = ("none", (string?)null);
            if (BearerOf(http.Request.Headers.Authorization.ToString()) is { } b) (source, token) = ("bearer", b);
            else
            {
                string? saved = null;
                try { saved = await http.GetTokenAsync("id_token"); } catch (InvalidOperationException) { saved = null; }
                if (!string.IsNullOrWhiteSpace(saved)) (source, token) = ("session", saved);
            }
            var actor = scope.Actor ?? "";
            await _sql.QueryAsync(InsertSql, new Dictionary<string, object?>
            {
                ["Cid"] = scope.CorrelationId, ["Action"] = scope.Action.Length > 128 ? scope.Action[..128] : scope.Action,
                ["Actor"] = actor.Length > 256 ? actor[..256] : actor, ["Source"] = source, ["Token"] = token,
                ["Aud"] = _audience.Length > 64 ? _audience[..64] : _audience,
            }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the signed-request record of {Action} could not be written (observe only -- nothing is refused)", scope.Action);
        }
    }
}
