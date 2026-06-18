using System.Text.Json.Nodes;
using Sia.Core.Ai;
using Sia.Core.Configuration;
using Sia.Web.Mcp;
using Sia.Web.Services;

// ===========================================================================
//  SecurityInsight Analyzer (SIA) - hosted, executive-grade web app.
//  Entry point. Wires the read-only data plane (Log Analytics via Managed
//  Identity, or demo fallback), the grounded AI narrative (Azure OpenAI,
//  AI-on by default in the hosted internal env, fail-soft), the exec + analyst
//  Razor surfaces, the JSON API and the read-only MCP endpoint.
//
//  AUTH: in Azure the platform's Easy Auth (Entra) sits IN FRONT of this app
//  (configured out-of-band on the App Service / Container App - see
//  deploy/README-DEPLOY.md). The app trusts the authenticated principal the
//  platform injects; a hosted analyzer of security findings is never anonymous.
// ===========================================================================

var builder = WebApplication.CreateBuilder(args);

// --- Options ---------------------------------------------------------------
var opts = new SiaOptions();
builder.Configuration.GetSection(SiaOptions.SectionName).Bind(opts);
builder.Services.AddSingleton(opts);

// --- Data plane: internal env is the DEFAULT base; demo is the explicit fallback.
var resolution = WorkspaceResolver.Resolve(opts.WorkspaceId, opts.UseDemoData);
builder.Services.AddSingleton(resolution);

builder.Services.AddSingleton<IRiskDataSource>(sp =>
{
    if (resolution.IsLive)
    {
        var log = sp.GetRequiredService<ILogger<LogAnalyticsRiskDataSource>>();
        return new LogAnalyticsRiskDataSource(resolution.WorkspaceId!, opts.TimelineLookbackDays, log);
    }
    // Demo fallback - seed shipped to App_Data by the csproj.
    var seed = Path.Combine(sp.GetRequiredService<IWebHostEnvironment>().ContentRootPath, "App_Data", "demo-snapshot.json");
    return new DemoRiskDataSource(seed);
});

// --- AI: grounded + fail-soft. ON by default when endpoint+deployment are set.
builder.Services.AddSingleton<IAiNarrativeService>(sp =>
    new AiNarrativeService(opts, sp.GetRequiredService<ILogger<AiNarrativeService>>()));

// --- Scheduled exec-summary email (fail-soft): options + SMTP sender + orchestrator +
//     in-host scheduler. No recipients / no SMTP => renders but never sends or crashes.
var emailOpts = new EmailScheduleOptions();
builder.Configuration.GetSection(EmailScheduleOptions.SectionName).Bind(emailOpts);
builder.Services.AddSingleton(emailOpts);
builder.Services.AddSingleton<IExecEmailSender>(sp =>
    new SmtpExecEmailSender(emailOpts, sp.GetRequiredService<ILogger<SmtpExecEmailSender>>()));
builder.Services.AddScoped<ExecEmailService>();
builder.Services.AddHostedService<ScheduledExecEmailHostedService>();

builder.Services.AddScoped<AnalyzerService>();
builder.Services.AddRazorPages();
builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseStaticFiles();

// Liveness / readiness for the host (slot warm-up, ACA probes).
app.MapHealthChecks("/health");

app.MapRazorPages();

// Default landing surface = the EXEC management view (Razor page at "/").
app.MapGet("/", () => Results.Redirect("/exec"));

// --- JSON API (consumed by the analyst SPA + the print/PDF view) -----------
var api = app.MapGroup("/api");

api.MapGet("/exec", async (AnalyzerService svc, string? period, CancellationToken ct) => Results.Json(await svc.GetExecAsync(period, ct)));
api.MapGet("/worklist", async (AnalyzerService svc, int? top, CancellationToken ct) => Results.Json(await svc.GetWorklistAsync(top ?? 100, ct)));
api.MapGet("/prestaged", (AnalyzerService svc) => Results.Json(svc.GetPrestaged().Select(a => new { a.Id, a.Title, a.Plain, a.Domain })));
api.MapGet("/management", async (AnalyzerService svc, CancellationToken ct) => Results.Json(await svc.GetManagementAsync(ct)));

// Board-deck export as a self-contained HTML document (for the print/PDF handout and for
// an emailer to attach/inline). Same grounded exec view as /board; ?period= supported.
api.MapGet("/board", async (AnalyzerService svc, string? period, CancellationToken ct) =>
{
    var vm = await svc.GetExecAsync(period, ct);
    return Results.Content(Sia.Web.Rendering.BoardDeckRenderer.Render(vm), "text/html");
});

// Prioritised remediation plan: the next actions ranked by risk-removed-per-effort.
api.MapGet("/remediation", async (AnalyzerService svc, int? top, CancellationToken ct) =>
    Results.Json(await svc.GetRemediationPlanAsync(top ?? 5, ct)));

// Drill-down on demand: the grounded evidence behind any headline number.
api.MapGet("/drilldown", async (AnalyzerService svc, string? dimension, string? key, int? top, CancellationToken ct) =>
    Results.Json(await svc.GetDrilldownAsync(dimension ?? "overall", key, top ?? 10, ct)));

// Exec glossary: plain-language "what these terms mean", grounded examples from the data.
api.MapGet("/glossary", async (AnalyzerService svc, CancellationToken ct) =>
    Results.Json(await svc.GetGlossaryAsync(ct)));

// Org coaching ("missing processes"): the leadership-level maturity / process gaps the
// finding patterns imply, grounded in the data; honest when no systemic gap stands out.
api.MapGet("/coaching", async (AnalyzerService svc, CancellationToken ct) =>
    Results.Json(await svc.GetOrgCoachingAsync(ct)));

// Maturity scorecard + roadmap: a rule-based maturity rating per leadership dimension grounded
// in the latest snapshot, plus a prioritised "mature here next" roadmap; honest on no data.
api.MapGet("/maturity", async (AnalyzerService svc, CancellationToken ct) =>
    Results.Json(await svc.GetMaturityAsync(ct)));

// Exec-summary email PREVIEW: render the grounded email body as HTML (no send) so an
// operator can eyeball exactly what the scheduled mail will contain.
api.MapGet("/email/preview", async (ExecEmailService email, CancellationToken ct) =>
{
    var msg = await email.RenderAsync(ct);
    return Results.Content(msg.HtmlBody, "text/html");
});

// Exec-summary email manual "send now" trigger. Fail-soft: returns a JSON result
// describing what happened (sent / not-configured / failed); never 500s on a config gap.
api.MapPost("/email/send", async (ExecEmailService email, CancellationToken ct) =>
{
    var r = await email.SendNowAsync(ct);
    return Results.Json(new { r.Sent, r.RecipientCount, r.Detail });
});

api.MapPost("/prestaged/run", async (AnalyzerService svc, PrestagedRequest req, CancellationToken ct) =>
    Results.Json(await svc.RunPrestagedAsync(req.Id, ParseAudience(req.Audience), ct)));

api.MapPost("/adhoc", async (AnalyzerService svc, AdHocRequest req, CancellationToken ct) =>
    Results.Json(await svc.RunAdHocAsync(req.Question, ParseAudience(req.Audience), ct)));

api.MapPost("/query", async (AnalyzerService svc, RawKqlRequest req, CancellationToken ct) =>
    Results.Json(await svc.RunRawKqlAsync(req.Kql, ParseAudience(req.Audience), ct)));

// --- MCP server endpoint (read-only, guardrailed, same grounding) ----------
app.MapPost("/mcp", async (HttpContext http, AnalyzerService svc, ExecEmailService email, CancellationToken ct) =>
{
    using var reader = new StreamReader(http.Request.Body);
    var body = await reader.ReadToEndAsync(ct);
    var node = JsonNode.Parse(body);
    if (node is null) return Results.BadRequest(new { error = "Invalid JSON-RPC request." });
    var resp = await McpServer.HandleAsync(node, svc, ct, email);
    return Results.Json(resp);
});

app.Run();

static Audience ParseAudience(string? a) =>
    string.Equals(a, "management", StringComparison.OrdinalIgnoreCase) ? Audience.Management : Audience.Analyst;

internal sealed record PrestagedRequest(string Id, string? Audience);
internal sealed record AdHocRequest(string Question, string? Audience);
internal sealed record RawKqlRequest(string Kql, string? Audience);

// Exposed so the test host (WebApplicationFactory) can reference the entry assembly.
public partial class Program { }
