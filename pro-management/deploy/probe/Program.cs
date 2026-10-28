using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SI.Management.Core;

// SecurityInsight Pro management -- post-deploy probe. Runs INSIDE the Container Apps environment (both apps have
// internal ingress) and prints one line per check: "PROBE <check> PASS|FAIL <detail>", then "PROBE-SUMMARY".
// Configuration (environment):
//   PROBE_WEB_URL, PROBE_MCP_URL          https://<app fqdn> (no trailing slash)
//   PROBE_TENANT_ID, PROBE_CLIENT_ID      the app registration the web app signs in with
//   PROBE_MCP_TOKEN_VIEWER / _ADMIN       bearer tokens for api://<client id> carrying ONLY that role (optional; never printed)
//   PROBE_CHAT_QUESTION                   optional: one real question through the chat service (needs Identity__*, Estate__*, Chat__*)
//   PROBE_LINGER_SECONDS                  keep the replica alive so its console log can be streamed (default 240)
var env = new ConfigurationBuilder().AddEnvironmentVariables().Build();
string Need(string k) => env[k] is { Length: > 0 } v ? v.TrimEnd('/') : throw new InvalidOperationException($"{k} is not set");
var web = Need("PROBE_WEB_URL");
var mcp = Need("PROBE_MCP_URL");
var tenant = Need("PROBE_TENANT_ID");
var clientId = Need("PROBE_CLIENT_ID");
int pass = 0, fail = 0;
void Report(string check, bool ok, string detail)
{
    if (ok) pass++; else fail++;
    Console.WriteLine($"PROBE {check} {(ok ? "PASS" : "FAIL")} {detail.ReplaceLineEndings(" ")}");
}

using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(100) };

async Task Check(string name, Func<Task> body)
{
    try { await body(); }
    catch (Exception ex) { Report(name, false, ex.GetType().Name + ": " + ex.Message); }
}

// 1. health endpoints (the only anonymous route of each app)
foreach (var (name, url) in new[] { ("web-healthz", web), ("mcp-healthz", mcp) })
{
    await Check(name, async () =>
    {
        using var r = await http.GetAsync(url + "/healthz");
        var body = (await r.Content.ReadAsStringAsync()).Trim();
        Report(name, r.StatusCode == HttpStatusCode.OK && body == "ok", $"{(int)r.StatusCode} '{body}'");
    });
}

// 2. an unauthenticated page request is sent to Entra sign-in, for THIS app, back to THIS host, asking for an ID token
await Check("web-signin-redirect", async () =>
{
    using var r = await http.GetAsync(web + "/Management");
    var loc = r.Headers.Location?.ToString() ?? "";
    var q = System.Web.HttpUtility.ParseQueryString(r.Headers.Location?.Query ?? "");
    var ok = (int)r.StatusCode is 302 or 303
             && loc.StartsWith($"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize", StringComparison.OrdinalIgnoreCase)
             && q["client_id"] == clientId
             && q["redirect_uri"] == web + "/signin-oidc";
    Report("web-signin-redirect", ok, $"{(int)r.StatusCode} -> {loc.Split('?')[0]} client_id={q["client_id"]} redirect_uri={q["redirect_uri"]} response_type={q["response_type"]} scope={q["scope"]}");
});
await Check("web-static-needs-signin", async () =>
{
    using var r = await http.GetAsync(web + "/css/site.css");
    Report("web-static-needs-signin", (int)r.StatusCode is 302 or 303 or 401, $"{(int)r.StatusCode} (an asset is not served before sign-in)");
});

// 3. MCP: 401 without a token, and with a token that is not for this API
static HttpRequestMessage Rpc(string url, string method, object? @params, int id, string? token)
{
    var req = new HttpRequestMessage(HttpMethod.Post, url + "/mcp")
    {
        Content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id, method, @params }), Encoding.UTF8, "application/json"),
    };
    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
    if (token is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    return req;
}
static JsonElement? ParseRpc(string body)
{
    // streamable HTTP answers either JSON or an SSE stream whose "data:" lines carry the JSON-RPC message
    var json = body.TrimStart().StartsWith('{') ? body
        : string.Join("", body.Split('\n').Where(l => l.StartsWith("data:", StringComparison.Ordinal)).Select(l => l[5..].Trim()));
    if (string.IsNullOrWhiteSpace(json)) return null;
    using var d = JsonDocument.Parse(json);
    return d.RootElement.Clone();
}
var init = new { protocolVersion = "2025-06-18", capabilities = new { }, clientInfo = new { name = "si-management-probe", version = "1" } };
await Check("mcp-no-token-401", async () =>
{
    using var r = await http.SendAsync(Rpc(mcp, "initialize", init, 1, null));
    Report("mcp-no-token-401", r.StatusCode == HttpStatusCode.Unauthorized, $"{(int)r.StatusCode} www-authenticate={r.Headers.WwwAuthenticate}");
});
await Check("mcp-garbage-token-401", async () =>
{
    using var r = await http.SendAsync(Rpc(mcp, "initialize", init, 1, "not-a-token"));
    Report("mcp-garbage-token-401", r.StatusCode == HttpStatusCode.Unauthorized, $"{(int)r.StatusCode}");
});

async Task McpWithToken(string role, string token, bool expectSettings)
{
    using (var r = await http.SendAsync(Rpc(mcp, "initialize", init, 1, token)))
    {
        var body = await r.Content.ReadAsStringAsync();
        var m = ParseRpc(body);
        var server = m?.GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString();
        Report($"mcp-{role}-initialize", r.IsSuccessStatusCode && server is not null, $"{(int)r.StatusCode} server={server}");
    }
    using (var r = await http.SendAsync(Rpc(mcp, "tools/list", new { }, 2, token)))
    {
        var body = await r.Content.ReadAsStringAsync();
        var m = ParseRpc(body);
        var names = m?.GetProperty("result").GetProperty("tools").EnumerateArray().Select(t => t.GetProperty("name").GetString()).ToList() ?? new();
        var hasSettings = names.Contains(EstateToolbox.SettingsRead);
        Report($"mcp-{role}-tools-list", r.IsSuccessStatusCode && names.Count >= 6 && hasSettings == expectSettings,
               $"{(int)r.StatusCode} {names.Count} tools: {string.Join(", ", names)}");
    }
    using (var r = await http.SendAsync(Rpc(mcp, "tools/call", new { name = EstateToolbox.TopRisks, arguments = new { top = 3 } }, 3, token)))
    {
        var body = await r.Content.ReadAsStringAsync();
        var m = ParseRpc(body);
        var result = m?.GetProperty("result");
        var isError = result?.TryGetProperty("isError", out var e) == true && e.GetBoolean();
        var text = result?.GetProperty("content")[0].GetProperty("text").GetString() ?? "";
        string detail;
        try
        {
            using var d = JsonDocument.Parse(text);
            var data = d.RootElement.GetProperty("data");
            var top = data.ValueKind == JsonValueKind.Array && data.GetArrayLength() > 0 ? data[0] : default;
            detail = $"{data.GetArrayLength()} assets; #1 {(top.ValueKind == JsonValueKind.Object ? top.GetProperty("assetName").GetString() + " tier " + top.GetProperty("tier").GetString() : "-")}; query carried: {d.RootElement.TryGetProperty("query", out _)}";
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException) { detail = text.Length > 300 ? text[..300] : text; }
        Report($"mcp-{role}-top_risks", r.IsSuccessStatusCode && !isError, $"{(int)r.StatusCode} {detail}");
    }
    // settings_read reads cfg in the Pro database: allowed for Admin, refused for Viewer
    using (var r = await http.SendAsync(Rpc(mcp, "tools/call", new { name = EstateToolbox.SettingsRead, arguments = new { rows = 3 } }, 4, token)))
    {
        var body = await r.Content.ReadAsStringAsync();
        var m = ParseRpc(body);
        var refused = m is null || m.Value.TryGetProperty("error", out _)
                      || (m.Value.TryGetProperty("result", out var res) && res.TryGetProperty("isError", out var ie) && ie.GetBoolean());
        var snippet = body.Length > 240 ? body[..240] : body;
        Report($"mcp-{role}-settings_read-{(expectSettings ? "allowed" : "refused")}", expectSettings ? (r.IsSuccessStatusCode && !refused) : refused,
               $"{(int)r.StatusCode} {snippet}");
    }
}
if (env["PROBE_MCP_TOKEN_VIEWER"] is { Length: > 0 } viewerToken)
    await Check("mcp-viewer", () => McpWithToken("viewer", viewerToken, expectSettings: false));
if (env["PROBE_MCP_TOKEN_ADMIN"] is { Length: > 0 } adminToken)
    await Check("mcp-admin", () => McpWithToken("admin", adminToken, expectSettings: true));

// 4. chat: one real question through the chat service, against the real Azure OpenAI deployment, as the web identity
if (env["PROBE_CHAT_QUESTION"] is { Length: > 0 } question)
{
    await Check("chat", async () =>
    {
        var services = new ServiceCollection();
        services.AddSecurityInsightEstate(env);
        await using var sp = services.BuildServiceProvider();
        var chat = sp.GetRequiredService<IChatService>();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var answer = await chat.AskAsync(Array.Empty<ChatTurn>(), question, isAdmin: false, CancellationToken.None);
        Console.WriteLine("CHAT-QUESTION " + question);
        Console.WriteLine("CHAT-ANSWER-BEGIN");
        Console.WriteLine(answer.Text);
        Console.WriteLine("CHAT-ANSWER-END");
        foreach (var t in answer.ToolCalls)
            Console.WriteLine($"CHAT-TOOLCALL {t.Tool} args={t.ArgumentsJson} source={t.Source} query={t.Query.ReplaceLineEndings(" ")[..Math.Min(t.Query.Length, 400)]}");
        Report("chat", answer.ToolCalls.Count > 0 && answer.Text.Length > 0,
               $"{answer.ToolCalls.Count} tool call(s) in {sw.Elapsed.TotalSeconds:0.0}s: {string.Join(", ", answer.ToolCalls.Select(t => t.Tool))}");
    });
}

// 5. the Pro database as THIS job's identity (the web app's, when run by Test-SIManagementDeployment.ps1): cfg + vuln reads
if (env["Estate:SqlServer"] is { Length: > 0 })
{
    await Check("sql-as-identity", async () =>
    {
        var services = new ServiceCollection();
        services.AddSecurityInsightEstate(env);
        await using var sp = services.BuildServiceProvider();
        var tools = sp.GetRequiredService<EstateToolbox>();
        var settings = await tools.InvokeAsync(EstateToolbox.SettingsRead, "{\"rows\":3}", isAdmin: true, CancellationToken.None);
        var vuln = await tools.InvokeAsync(EstateToolbox.VulnerabilityStateTool, "{\"weeks\":4}", isAdmin: false, CancellationToken.None);
        using var s1 = JsonDocument.Parse(settings.ResultJson);
        using var v1 = JsonDocument.Parse(vuln.ResultJson);
        Report("sql-as-identity", true, $"settings_read {settings.ResultJson.Length} chars from {settings.Source}; vulnerability_state {vuln.ResultJson.Length} chars from {vuln.Source}");
    });
}

Console.WriteLine($"PROBE-SUMMARY pass={pass} fail={fail}");
var linger = int.TryParse(env["PROBE_LINGER_SECONDS"], out var s) ? s : 240;
await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(linger, 0, 1800)));
return fail == 0 ? 0 : 1;
