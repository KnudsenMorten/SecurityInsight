using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SI.Management.Web.Settings;

/// <summary>
/// Exchange Online administration WITHOUT the PowerShell module: the same REST call the ExchangeOnlineManagement module
/// makes -- POST https://outlook.office365.com/adminapi/beta/{tenantId}/InvokeCommand with
/// {"CmdletInput":{"CmdletName":..., "Parameters":{...}}}; 200 + {"value":[...]} = done, {"error":{"code","message"}} =
/// the Exchange error text. Used by the guided mail setup (Settings > E-mail + links > Set up mail).
/// </summary>
public interface IExchangeAdminClient
{
    Task<ExchangeCallResult> InvokeAsync(ExchangeSession session, string cmdlet, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct);
}

/// Who calls Exchange, for which tenant: the bearer token and the X-AnchorMailbox header (see <see cref="ExchangeAdminClient.Anchor"/>).
public sealed record ExchangeSession(string TenantId, string AccessToken, string AnchorMailbox);

public enum ExchangeOutcome { Ok, AlreadyExists, NeedsRole, Failed }

/// One cmdlet's answer: the outcome, the HTTP status, the message (Exchange's error text, or empty) and the value rows.
public sealed record ExchangeCallResult(ExchangeOutcome Outcome, int Status, string Message, IReadOnlyList<JsonElement> Rows)
{
    /// Done -- or there already (an 'already exists' error counts as done for an idempotent setup step).
    public bool Succeeded => Outcome is ExchangeOutcome.Ok or ExchangeOutcome.AlreadyExists;
}

public sealed class ExchangeAdminClient : IExchangeAdminClient
{
    public const string Resource = "https://outlook.office365.com";
    /// The signed-in admin's delegated scope (requested incrementally, only for the guided setup).
    public const string DelegatedScope = "https://outlook.office365.com/Exchange.Manage";
    /// An app-only token's scope (an app context, e.g. a support app with configured credentials).
    public const string AppScope = "https://outlook.office365.com/.default";
    /// The arbitration mailbox Exchange anchors app-only admin calls on.
    public const string AppAnchorMailbox = "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}";

    private readonly HttpClient _http;
    public ExchangeAdminClient(HttpClient http) => _http = http;

    public static string Url(string tenantId) => $"{Resource}/adminapi/beta/{Uri.EscapeDataString(tenantId.Trim())}/InvokeCommand";

    /// X-AnchorMailbox: "UPN:&lt;admin&gt;" for the signed-in admin's delegated token; for an app-only token
    /// "APP:SystemMailbox{bb558c35-...}@&lt;tenant initial domain&gt;".
    public static string Anchor(bool appOnly, string? adminUpn, string? tenantInitialDomain) =>
        appOnly ? "APP:" + AppAnchorMailbox + "@" + (tenantInitialDomain ?? "").Trim() : "UPN:" + (adminUpn ?? "").Trim();

    /// The request body: {"CmdletInput":{"CmdletName":"New-Mailbox","Parameters":{"Shared":true,...}}}.
    public static string BuildInvokeCommandJson(string cmdlet, IReadOnlyDictionary<string, object?> parameters)
    {
        var p = new JsonObject();
        foreach (var (k, v) in parameters)
            p[k] = v switch
            {
                null => null,
                bool b => JsonValue.Create(b),
                int i => JsonValue.Create(i),
                long l => JsonValue.Create(l),
                string s => JsonValue.Create(s),
                _ => JsonValue.Create(Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture)),
            };
        return new JsonObject { ["CmdletInput"] = new JsonObject { ["CmdletName"] = cmdlet, ["Parameters"] = p } }.ToJsonString();
    }

    /// An Exchange error that means "it is there already" (an idempotent step is then done).
    public static bool IsAlreadyExists(string? message) =>
        message is not null && (message.Contains("already exists", StringComparison.OrdinalIgnoreCase)
                                || message.Contains("already exist", StringComparison.OrdinalIgnoreCase));

    public async Task<ExchangeCallResult> InvokeAsync(ExchangeSession session, string cmdlet, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, Url(session.TenantId))
        {
            Content = new StringContent(BuildInvokeCommandJson(cmdlet, parameters), Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.AccessToken);
        req.Headers.TryAddWithoutValidation("X-ResponseFormat", "json");
        req.Headers.TryAddWithoutValidation("X-AnchorMailbox", session.AnchorMailbox);
        HttpResponseMessage resp;
        try { resp = await _http.SendAsync(req, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return new ExchangeCallResult(ExchangeOutcome.Failed, 0, "Exchange Online could not be reached: " + ex.Message, Array.Empty<JsonElement>());
        }
        using (resp)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            var (rows, error) = ParseBody(body);
            var status = (int)resp.StatusCode;
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return new ExchangeCallResult(ExchangeOutcome.NeedsRole, status, error ?? resp.ReasonPhrase ?? "", rows);
            if (resp.IsSuccessStatusCode && error is null) return new ExchangeCallResult(ExchangeOutcome.Ok, status, "", rows);
            var message = error ?? $"Exchange Online answered {status} {resp.ReasonPhrase}";
            return new ExchangeCallResult(IsAlreadyExists(message) ? ExchangeOutcome.AlreadyExists : ExchangeOutcome.Failed, status, message, rows);
        }
    }

    /// The value rows and the error message of an InvokeCommand answer.
    internal static (IReadOnlyList<JsonElement> Rows, string? Error) ParseBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return (Array.Empty<JsonElement>(), null);
        try
        {
            using var doc = JsonDocument.Parse(body);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return (Array.Empty<JsonElement>(), null);
            string? error = null;
            if (o.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.Object)
            {
                var code = e.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
                var msg = e.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
                error = string.IsNullOrWhiteSpace(msg) ? code ?? "Exchange Online returned an error" : msg;
            }
            var rows = o.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Array
                ? v.EnumerateArray().Select(x => x.Clone()).ToList()
                : new List<JsonElement>();
            return (rows, error);
        }
        catch (JsonException) { return (Array.Empty<JsonElement>(), body.Length > 300 ? body[..300] : body); }
    }
}

/// An Exchange administration token: the bearer and whether it is app-only (which changes the anchor mailbox).
public sealed record ExchangeToken(string AccessToken, bool AppOnly);

/// <summary>
/// Where the Exchange token comes from. Today: the signed-in admin's DELEGATED token (Exchange.Manage) through
/// Microsoft.Identity.Web, when token acquisition is configured. An app-only source (scope
/// https://outlook.office365.com/.default from configured app credentials -- e.g. the support app context) plugs in
/// here; it returns AppOnly = true and the calls then anchor on the arbitration mailbox.
/// </summary>
public interface IExchangeTokenSource
{
    /// False = the web app cannot sign in to Exchange on the admin's behalf on this install.
    bool IsAvailable { get; }
    Task<ExchangeToken> GetAsync(ClaimsPrincipal user, CancellationToken ct);
}

/// The signed-in admin's delegated token through ITokenAcquisition (registered only when the app has credentials).
/// A token that needs consent first throws MicrosoftIdentityWebChallengeUserException -- the page's
/// [AuthorizeForScopes] turns it into the incremental-consent sign-in.
public sealed class DelegatedExchangeTokenSource : IExchangeTokenSource
{
    private readonly IServiceProvider _sp;
    private readonly IHttpContextAccessor _http;
    public DelegatedExchangeTokenSource(IServiceProvider sp, IHttpContextAccessor http) { _sp = sp; _http = http; }

    /// Registered = Program.cs enabled token acquisition (the app has credentials). Asked of the container, not resolved.
    public bool IsAvailable =>
        _sp.GetService(typeof(Microsoft.Extensions.DependencyInjection.IServiceProviderIsService)) is Microsoft.Extensions.DependencyInjection.IServiceProviderIsService probe
        && probe.IsService(typeof(Microsoft.Identity.Web.ITokenAcquisition));

    public async Task<ExchangeToken> GetAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        // resolved from the request's services (the token acquisition may be registered per request)
        var services = _http.HttpContext?.RequestServices ?? _sp;
        var ta = services.GetService(typeof(Microsoft.Identity.Web.ITokenAcquisition)) as Microsoft.Identity.Web.ITokenAcquisition
                 ?? throw new InvalidOperationException("token acquisition is not configured on this install");
        // positional (scopes, tenantId, userFlow, user): the overload without an authentication scheme
        var token = await ta.GetAccessTokenForUserAsync(new[] { ExchangeAdminClient.DelegatedScope }, null, null, user);
        return new ExchangeToken(token, false);
    }

    /// Whether the AzureAd section carries client credentials, so Microsoft.Identity.Web can acquire tokens.
    public static bool CanAcquire(IConfiguration azureAd) =>
        !string.IsNullOrWhiteSpace(azureAd["ClientSecret"])
        || azureAd.GetSection("ClientCredentials").GetChildren().Any()
        || azureAd.GetSection("ClientCertificates").GetChildren().Any();
}
