using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using SI.Management.Core;
using SI.Management.Core.Licensing;
using SI.Management.Mcp;

// SecurityInsight MCP server (Pro-5): curated, read-only tools over the estate's data, streamable HTTP.
// Every request needs an Entra bearer token for this app with an app role (Viewer = Reader, Admin, SuperAdmin); settings_read needs Admin or SuperAdmin.
// PERSON-ONLY (framework SECURE-WEB-1 (3)): a person's delegated token whose scp carries mcp.access; an application's
// token, an ID token or a token for another scope is refused (McpCaller.cs).
// DISCOVERY (RFC 9728, McpDiscovery.cs): /.well-known/oauth-protected-resource[/mcp] answers without a sign-in -- which
// resource, which authorization server, which scope; no data -- and this server's own 401s name it.
// Configuration: "AzureAd" (the API app registration), "Identity" (how THIS process reads LA/SQL: managed identity
// hosted, certificate locally), "Estate" (workspace + SQL), optional "Mcp:PublicBaseUrl". No value is hard-coded.
var builder = WebApplication.CreateBuilder(args);

var discovery = McpDiscovery.FromConfiguration(builder.Configuration);
builder.Services.AddSingleton(discovery);
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));
// this server's own 401 names the RFC 9728 document (chained after any handler Microsoft.Identity.Web set)
builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o =>
{
    o.Events ??= new JwtBearerEvents();
    var before = o.Events.OnChallenge;
    o.Events.OnChallenge = async ctx =>
    {
        if (before is not null) await before(ctx);
        if (!ctx.Handled) await discovery.OnChallenge(ctx);
    };
});
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy(McpRoles.ReaderPolicy, p => p.RequireAuthenticatedUser()
        .RequireRole(McpRoles.Viewer, McpRoles.Reader, McpRoles.Admin, McpRoles.SuperAdmin)
        .RequireAssertion(ctx => McpCallerRule.IsPersonMcpToken(ctx.User)));
});
builder.Services.AddHttpContextAccessor();
builder.Services.AddSecurityInsightEstate(builder.Configuration);
// THE LICENCE GATE (owner 2026-10-27, SI #750 (3)): deployed in every install, answering only with a Pro licence on record
builder.Services.AddSingleton<McpLicenceGate>(sp => new McpLicenceGate(sp.GetRequiredService<ISqlReader>()));
// WHO the caller is in THIS install: the access table decides (McpCaller.cs), as in the web app
builder.Services.AddSingleton<McpCallerResolver>(sp => new McpCallerResolver(sp.GetRequiredService<ISqlReader>()));
// PER-CALLER LIMITS: a caller (object id, else the calling application) gets at most McpLimits:Concurrent calls at once and
// McpLimits:PerMinute calls a minute; past either the answer is 429 -- one caller can never hold the shared Pro database
var perMinute = builder.Configuration.GetValue("McpLimits:PerMinute", CallerLimits.DefaultMcpPerMinute);
var concurrent = builder.Configuration.GetValue("McpLimits:Concurrent", CallerLimits.DefaultMcpConcurrent);
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.GlobalLimiter = CallerLimits.Create<HttpContext>(ctx => ctx.Request.Path.StartsWithSegments("/mcp") ? McpCallerRule.PartitionKey(ctx.User) : null, perMinute, concurrent);
    // /mcp only (the health probe is never limited), keyed on the signed-in caller
});

builder.Services
    .AddMcpServer(o =>
    {
        o.ServerInfo = new() { Name = "securityinsight-estate", Version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0" };
        o.ServerInstructions = "Read-only SecurityInsight estate data. Every tool result carries the query that produced it; cite it. " + UntrustedData.Notice;
    })
    .WithHttpTransport(o => o.Stateless = true)
    .AddAuthorizationFilters()
    .WithTools<EstateMcpTools>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// THE LICENCE GATE (owner 2026-10-27, SI #750 (3)): the MCP server is Pro. It is deployed in every install (Community edition
// and Pro) and answers /mcp only while the installed licence (cfg.InstallState 'Licence', the updater's verified record)
// names a Pro edition in force -- so a licence bought later switches it on, and a removed / ended one switches it off,
// without a redeploy. DENY BY DEFAULT (no record, unreadable, database down = 403). /healthz and the RFC 9728 discovery
// document stay open (neither is under /mcp, and neither carries data).
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/mcp") && !await ctx.RequestServices.GetRequiredService<McpLicenceGate>().IsProAsync(ctx.RequestAborted))
    {
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        await ctx.Response.WriteAsync(McpLicenceGate.RefusalBody(), ctx.RequestAborted);
        return;
    }
    await next();
});

app.MapGet("/healthz", () => Results.Text("ok")).AllowAnonymous();
// RFC 9728 discovery: anonymous, never rate limited, outside the licence gate (not under /mcp); the root form and /mcp only
app.MapGet(McpDiscovery.WellKnownPath, (HttpContext ctx, McpDiscovery d) => d.Answer(ctx, null)).AllowAnonymous().DisableRateLimiting();
app.MapGet(McpDiscovery.WellKnownPath + "/{**rest}", (HttpContext ctx, McpDiscovery d, string? rest) => d.Answer(ctx, rest)).AllowAnonymous().DisableRateLimiting();
app.MapMcp("/mcp").RequireAuthorization(McpRoles.ReaderPolicy);

app.Run();

public partial class Program;
