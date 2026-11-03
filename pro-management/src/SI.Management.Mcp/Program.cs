using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using SI.Management.Core;
using SI.Management.Core.Licensing;
using SI.Management.Mcp;

// SecurityInsight MCP server (Pro-5): curated, read-only tools over the estate's data, streamable HTTP.
// Every request needs an Entra bearer token for this app with an app role (Viewer = Reader, Admin, SuperAdmin); settings_read needs Admin or SuperAdmin.
// Configuration: "AzureAd" (the API app registration), "Identity" (how THIS process reads LA/SQL: managed identity
// hosted, certificate locally), "Estate" (workspace + SQL). No value is hard-coded.
var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy(McpRoles.ReaderPolicy, p => p.RequireAuthenticatedUser().RequireRole(McpRoles.Viewer, McpRoles.Reader, McpRoles.Admin, McpRoles.SuperAdmin));
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
// without a redeploy. DENY BY DEFAULT (no record, unreadable, database down = 403). /healthz stays open.
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
app.MapMcp("/mcp").RequireAuthorization(McpRoles.ReaderPolicy);

app.Run();

public partial class Program;
