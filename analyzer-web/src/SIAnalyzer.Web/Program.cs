using System.Text.Json.Nodes;
using Microsoft.AspNetCore.HttpOverrides;
using SIAnalyzer.Core.Ai;
using SIAnalyzer.Core.Configuration;
using SIAnalyzer.Web.Auth;
using SIAnalyzer.Web.Mcp;
using SIAnalyzer.Web.Security;
using SIAnalyzer.Web.Services;

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
var opts = new SIAnalyzerOptions();
builder.Configuration.GetSection(SIAnalyzerOptions.SectionName).Bind(opts);
builder.Services.AddSingleton(opts);

// --- Auth: end-to-end validation of the Easy Auth client principal + the /mcp gate.
//     Platform Entra Easy Auth sits in front of the container; the app trusts + parses
//     X-MS-CLIENT-PRINCIPAL and (when SIAnalyzer:Auth:RequireClientPrincipal is on) keeps the MCP
//     tool surface behind the SAME authenticated principal as the UI (never anonymous).
var authOpts = new EasyAuthOptions();
builder.Configuration.GetSection(EasyAuthOptions.SectionName).Bind(authOpts);
builder.Services.AddSingleton(authOpts);

// --- MCP surface (audit #11): the agent-facing endpoint is read-only by default. The one tool
//     with an external side effect (sending the exec email) is opt-in, and refused - not merely
//     unlisted - while it is off.
var mcpOpts = new McpOptions();
builder.Configuration.GetSection(McpOptions.SectionName).Bind(mcpOpts);
builder.Services.AddSingleton(mcpOpts);

// --- Data plane: internal env is the DEFAULT base; demo is the explicit fallback.
var resolution = WorkspaceResolver.Resolve(opts.WorkspaceId, opts.UseDemoData);
builder.Services.AddSingleton(resolution);

builder.Services.AddSingleton<IRiskDataSource>(sp =>
{
    if (resolution.IsLive)
    {
        var log = sp.GetRequiredService<ILogger<LogAnalyticsRiskDataSource>>();
        var live = new LogAnalyticsRiskDataSource(resolution.WorkspaceId!, opts.TimelineLookbackDays, log);
        // AUDIT #10: one rollup shared by all eight AnalyzerService entry points instead of a
        // 500k-row query per call. A partial read is never cached (see CachedRiskDataSource), and
        // ad-hoc analyst queries pass straight through.
        return opts.RollupCacheSeconds > 0
            ? new CachedRiskDataSource(live, TimeSpan.FromSeconds(opts.RollupCacheSeconds))
            : (IRiskDataSource)live;
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

// AUDIT #9: "has this window already been sent?" must be shared across replicas and survive a
// restart. Same storage account as the governance register, its own table.
var scheduleOpts = new ScheduleStorageOptions();
builder.Configuration.GetSection(ScheduleStorageOptions.SectionName).Bind(scheduleOpts);
builder.Services.AddSingleton(scheduleOpts);
builder.Services.AddSingleton<SIAnalyzer.Core.Scheduling.ISendMarkerStore>(sp =>
{
    var log = sp.GetRequiredService<ILogger<Program>>();
    if (string.IsNullOrWhiteSpace(scheduleOpts.TableEndpoint))
    {
        return new SIAnalyzer.Core.Scheduling.InMemorySendMarkerStore();
    }
    try
    {
        var client = new Azure.Data.Tables.TableServiceClient(
            new Uri(scheduleOpts.TableEndpoint), new Azure.Identity.DefaultAzureCredential());
        var table = client.GetTableClient(scheduleOpts.TableName);
        table.CreateIfNotExists();
        var account = new Uri(scheduleOpts.TableEndpoint).Host.Split('.')[0];
        return new TableSendMarkerStore(table, $"Azure Table Storage ({account}/{scheduleOpts.TableName})");
    }
    catch (Exception ex)
    {
        // Fail-soft but loud: the app still serves. The scheduler logs at startup that its
        // marker is not durable, so a double-send is not mistaken for a fixed one.
        log.LogError(ex, "Scheduler marker table is unreachable ({Endpoint}); falling back to an IN-MEMORY send marker. The exec email can double-send across replicas.", scheduleOpts.TableEndpoint);
        return new SIAnalyzer.Core.Scheduling.InMemorySendMarkerStore();
    }
});
builder.Services.AddHostedService<ScheduledExecEmailHostedService>();

// --- Governance store (Phase 6): the ONLY write surface. The LOCAL register is on by default
//     (it writes to SIA's own table and never touches a platform); platform exemption sync is
//     HARD-LOCKED off in Core (no-auto-revoke) until tested.
//
//     AUDIT #7: the register is DURABLE when SIAnalyzer:Governance:TableEndpoint is set - Azure
//     Table Storage via the app's Managed Identity, so records survive a restart/redeploy and
//     two replicas read the same register. With no endpoint configured it falls back to the
//     in-memory store, which the governance page then labels as not durable rather than
//     presenting a volatile list as a register of record.
var govOpts = new GovernanceOptions();
builder.Configuration.GetSection(GovernanceOptions.SectionName).Bind(govOpts);
builder.Services.AddSingleton(govOpts);
builder.Services.AddSingleton<SIAnalyzer.Core.Governance.IGovernancePersistence>(sp =>
{
    var log = sp.GetRequiredService<ILogger<Program>>();
    if (string.IsNullOrWhiteSpace(govOpts.TableEndpoint))
    {
        log.LogWarning("Governance register is IN-MEMORY: SIAnalyzer:Governance:TableEndpoint is not set, so records do not survive a restart and are not shared between replicas.");
        return new SIAnalyzer.Core.Governance.InMemoryGovernancePersistence();
    }
    try
    {
        var client = new Azure.Data.Tables.TableServiceClient(
            new Uri(govOpts.TableEndpoint), new Azure.Identity.DefaultAzureCredential());
        var table = client.GetTableClient(govOpts.TableName);
        table.CreateIfNotExists();
        var account = new Uri(govOpts.TableEndpoint).Host.Split('.')[0];
        log.LogInformation("Governance register is DURABLE: table {Table} in {Account}.", govOpts.TableName, account);
        return new TableGovernancePersistence(table, $"Azure Table Storage ({account}/{govOpts.TableName})");
    }
    catch (Exception ex)
    {
        // Fail-soft, but LOUD and honest: the app still serves, the register still works for
        // this instance, and the page says the records are not durable. Silently degrading to
        // RAM while the page claims a register of record is exactly audit #7.
        log.LogError(ex, "Governance table storage is unreachable ({Endpoint}); falling back to the IN-MEMORY register. Records will NOT survive a restart.", govOpts.TableEndpoint);
        return new SIAnalyzer.Core.Governance.InMemoryGovernancePersistence();
    }
});
builder.Services.AddSingleton(sp => new SIAnalyzer.Core.Governance.GovernanceStore(
    govOpts.ToCapabilities(),
    sp.GetRequiredService<SIAnalyzer.Core.Governance.IGovernancePersistence>()));
// AUDIT #8: SweepExpired had no production caller, so expiry never fired at runtime.
builder.Services.AddHostedService<GovernanceExpirySweepService>();

builder.Services.AddScoped<AnalyzerService>();
builder.Services.AddRazorPages();
builder.Services.AddHealthChecks();

var app = builder.Build();

// --- FORWARDED HEADERS (audit #13) -----------------------------------------
// MUST be first: everything below that asks "is this request HTTPS?" is wrong without it.
//
// Container Apps terminates TLS at the ingress and forwards plain HTTP to the container with
// X-Forwarded-Proto: https. Nothing here honoured that, which quietly disarmed the two things
// #13 asked for:
//   * UseHsts() emits NOTHING on a non-HTTPS request -- the header would never have appeared.
//     That is the same "armed but not firing" shape as audit #1/#3/#7/#9.
//   * UseHttpsRedirection() would have seen every request as HTTP and redirected FOREVER.
// So the honest fix is this middleware first, HSTS after it, and NO in-app redirection: the
// platform already refuses plain HTTP when ingress.allowInsecure is false, and Deploy-SIAnalyzer.ps1
// now ASSERTS that (the #12 pattern -- enforce it where it is actually enforceable).
//
// KnownNetworks/KnownProxies are cleared because the ACA ingress address is not knowable in
// advance. The trade-off, stated plainly: a caller that reaches the container directly could spoof
// X-Forwarded-Proto. Behind private ingress nothing can, and the blast radius is limited to HSTS
// emission and generated absolute URLs -- it grants no authorisation. (Auth is a separate trust,
// still X-MS-CLIENT-PRINCIPAL as supplied -- see #3's residual item.)
var fwd = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor
};
fwd.KnownNetworks.Clear();
fwd.KnownProxies.Clear();
app.UseForwardedHeaders(fwd);

// --- SECURITY HEADERS + CSP (audit #13) ------------------------------------
// Before the auth gate on purpose, so even the 401 body carries them.
app.UseSIAnalyzerSecurityHeaders();

// HSTS only bites once the request is seen as HTTPS, which is what UseForwardedHeaders above
// makes true in the hosted environment. Locally (plain HTTP) it correctly emits nothing.
app.UseHsts();

app.UseStaticFiles();

// --- CSRF GUARD (audit #14) ------------------------------------------------
// Deliberately BEFORE the auth gate: a cross-site POST from a signed-in victim IS authenticated
// (Easy Auth injects the principal), so the auth gate would let it through. Rejecting it earlier
// also means a forged request never reaches the code that would send mail. Stateless by design --
// DataProtection keys are ephemeral here, so antiforgery tokens would break across replicas.
app.UseSIAnalyzerCsrfGuard();

// --- DEFAULT-DENY AUTHENTICATION GATE (audit #3 / #3a) ---------------------
// Operator directive 2026-08-05: "we need that this page is authenticated by default,
// except if we provide dashboards to internal audience".
//
// A BLANKET gate, deliberately not per-endpoint. Previously EasyAuth.RequireAuthenticated
// was invoked on exactly FOUR endpoints and everything else was anonymous - including
// POST /api/query (arbitrary guardrailed KQL against the live workspace),
// GET /api/governance (the exemption register, with owner names) and POST /api/email/send.
// That state arose by OMISSION, which is what a per-endpoint model invites: a new endpoint
// is anonymous unless someone remembers. Here a new endpoint is GATED unless someone
// explicitly opts it out.
//
// Runs after UseStaticFiles so CSS/JS still serve - they carry no data, and the pages
// referencing them are gated anyway.
//
// /health is ALWAYS open: ACA liveness probes and the deploy script's post-deploy health
// gate cannot present a principal, and it exposes no posture data.
app.Use(async (ctx, next) =>
{
    if (authOpts.RequireClientPrincipal)
    {
        var path = ctx.Request.Path.Value ?? "/";
        var alwaysOpen = string.Equals(path, "/health", StringComparison.OrdinalIgnoreCase);
        var exempt = authOpts.AnonymousPaths is { Length: > 0 } &&
                     authOpts.AnonymousPaths.Any(p =>
                         !string.IsNullOrWhiteSpace(p) &&
                         path.StartsWith(p.Trim(), StringComparison.OrdinalIgnoreCase));

        if (!alwaysOpen && !exempt && !SIAnalyzer.Web.Auth.EasyAuth.IsAuthenticated(ctx))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsJsonAsync(new
            {
                error = "Unauthenticated. SecurityInsight Analyzer requires an Entra-authenticated principal (Easy Auth).",
                path
            });
            return;
        }
    }
    await next();
});

// Liveness / readiness for the host (slot warm-up, ACA probes).
app.MapHealthChecks("/health");

app.MapRazorPages();

// Default landing surface = the EXEC management view (Razor page at "/").
app.MapGet("/", () => Results.Redirect("/exec"));

// --- JSON API (consumed by the analyst SPA + the print/PDF view) -----------
var api = app.MapGroup("/api");

// Who am I? Validates the Easy Auth client principal end-to-end (parses
// X-MS-CLIENT-PRINCIPAL the platform injects) and reflects the authenticated identity.
// When the gate is on, anonymous callers get 401 here too.
api.MapGet("/me", (HttpContext http) =>
{
    var denied = EasyAuth.RequireAuthenticated(http, authOpts);
    if (denied is not null) return denied;
    var p = EasyAuth.GetPrincipal(http);
    return Results.Json(new
    {
        authenticated = p is not null,
        name = p?.Name,
        authType = p?.AuthenticationType,
        gateEnabled = authOpts.RequireClientPrincipal,
    });
});

// --- Governance (Phase 6): the ONLY write path. READS (register/audit/capabilities) are open;
//     WRITES are gated behind the same authenticated principal as the UI AND the store's own
//     capability flags (local register off => read-only; platform sync HARD-LOCKED off until
//     tested - the no-auto-revoke rule). The platform-writing surface is never enable-able here.
api.MapGet("/governance", (SIAnalyzer.Core.Governance.GovernanceStore store) => Results.Json(new
{
    capabilities = new
    {
        localRegisterEnabled = store.Capabilities.LocalRegisterEnabled,
        platformSyncEnabled = store.Capabilities.PlatformSyncEnabled,
        platformSyncLocked = SIAnalyzer.Core.Governance.GovernanceCapabilities.PlatformSyncLocked,
        platformSyncDisabledReason = store.Capabilities.PlatformSyncDisabledReason,
    },
    // AUDIT #7: say where the register lives and whether that survives a restart. A caller must
    // be able to tell a register of record from a volatile list without reading the deploy.
    storage = new
    {
        description = store.StorageDescription,
        durable = store.StorageIsDurable,
    },
    exemptions = store.Exemptions,
    riskAccepted = store.Comments,
    audit = store.Audit,
}));

api.MapPost("/governance/risk-accept", (HttpContext http, SIAnalyzer.Core.Governance.GovernanceStore store, RiskAcceptRequest req) =>
{
    var denied = EasyAuth.RequireAuthenticated(http, authOpts);
    if (denied is not null) return denied;
    var owner = EasyAuth.GetPrincipal(http)?.Name ?? req.Owner ?? "unknown";
    var r = store.AddRiskAcceptComment(req.FindingId, req.ConfigurationName, owner, req.Justification, req.Expiry);
    return Results.Json(new { r.Accepted, r.PlatformSynced, r.Detail, r.RecordId });
});

api.MapPost("/governance/exemption", (HttpContext http, SIAnalyzer.Core.Governance.GovernanceStore store, ExemptionRequest req) =>
{
    var denied = EasyAuth.RequireAuthenticated(http, authOpts);
    if (denied is not null) return denied;
    var owner = EasyAuth.GetPrincipal(http)?.Name ?? req.Owner ?? "unknown";
    var targets = (req.SyncTargets ?? Array.Empty<string>())
        .Select(t => Enum.TryParse<SIAnalyzer.Core.Governance.GovernancePlatform>(t, ignoreCase: true, out var p) ? (SIAnalyzer.Core.Governance.GovernancePlatform?)p : null)
        .Where(p => p is not null).Select(p => p!.Value).ToList();
    var r = store.RecordExemption(req.FindingId, req.ConfigurationName, req.Scope, owner, req.Reason, req.Expiry, targets);
    // PlatformSynced is ALWAYS false while the lock holds, even if targets were requested.
    return Results.Json(new { r.Accepted, r.PlatformSynced, r.Detail, r.RecordId });
});

// The renewal half of the expiry workflow. RenewExemption existed in the store from the start
// but had no endpoint, so an expiring exemption could only be recorded, never renewed.
api.MapPost("/governance/renew", (HttpContext http, SIAnalyzer.Core.Governance.GovernanceStore store, RenewRequest req) =>
{
    var denied = EasyAuth.RequireAuthenticated(http, authOpts);
    if (denied is not null) return denied;
    var actor = EasyAuth.GetPrincipal(http)?.Name ?? req.Actor ?? "unknown";
    var r = store.RenewExemption(req.ExemptionId, req.Expiry, actor);
    return Results.Json(new { r.Accepted, r.PlatformSynced, r.Detail, r.RecordId });
});

api.MapGet("/exec", async (AnalyzerService svc, string? period, CancellationToken ct) => Results.Json(await svc.GetExecAsync(period, ct)));
// Each row carries its governance state (audit #8) - risk-accepted / exempt findings are MARKED,
// never hidden and never removed from the score.
api.MapGet("/worklist", async (AnalyzerService svc, int? top, CancellationToken ct) => Results.Json(await svc.GetGovernedWorklistAsync(top ?? 100, ct)));
api.MapGet("/prestaged", (AnalyzerService svc) => Results.Json(svc.GetPrestaged().Select(a => new { a.Id, a.Title, a.Plain, a.Domain })));
api.MapGet("/management", async (AnalyzerService svc, CancellationToken ct) => Results.Json(await svc.GetManagementAsync(ct)));

// Board-deck export as a self-contained HTML document (for the print/PDF handout and for
// an emailer to attach/inline). Same grounded exec view as /board; ?period= supported.
api.MapGet("/board", async (AnalyzerService svc, HttpContext http, string? period, CancellationToken ct) =>
{
    var vm = await svc.GetExecAsync(period, ct);
    // Served by us, so it is governed by our CSP and needs the request's nonce (audit #13).
    return Results.Content(SIAnalyzer.Web.Rendering.BoardDeckRenderer.Render(vm, http.GetCspNonce()), "text/html");
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
// GATED behind the SAME authenticated principal as the UI: the MCP tool surface is never
// anonymous. When SIAnalyzer:Auth:RequireClientPrincipal is on, an anonymous call gets 401 before
// any tool runs (defense-in-depth on top of the platform Easy Auth gate).
app.MapPost("/mcp", async (HttpContext http, AnalyzerService svc, ExecEmailService email, McpOptions mcpOptions, ILoggerFactory logs, CancellationToken ct) =>
{
    var denied = EasyAuth.RequireAuthenticated(http, authOpts);
    if (denied is not null) return denied;

    using var reader = new StreamReader(http.Request.Body);
    var body = await reader.ReadToEndAsync(ct);
    var node = JsonNode.Parse(body);
    if (node is null) return Results.BadRequest(new { error = "Invalid JSON-RPC request." });
    var resp = await McpServer.HandleAsync(node, svc, ct, email, mcpOptions.AllowEmailSend, logs.CreateLogger("Mcp"));
    // AUDIT #11: a notification (no "id") gets NO response body - HandleAsync returns null and the
    // protocol requires silence. Serialising "null" with a 200 is not silence.
    return resp is null ? Results.NoContent() : Results.Json(resp);
});

app.Run();

static Audience ParseAudience(string? a) =>
    string.Equals(a, "management", StringComparison.OrdinalIgnoreCase) ? Audience.Management : Audience.Analyst;

internal sealed record PrestagedRequest(string Id, string? Audience);
internal sealed record AdHocRequest(string Question, string? Audience);
internal sealed record RawKqlRequest(string Kql, string? Audience);
internal sealed record RiskAcceptRequest(string FindingId, string ConfigurationName, string Justification, string? Owner, DateTimeOffset? Expiry);
internal sealed record ExemptionRequest(string FindingId, string ConfigurationName, string Scope, string Reason, DateTimeOffset Expiry, string[]? SyncTargets, string? Owner);
internal sealed record RenewRequest(string ExemptionId, DateTimeOffset Expiry, string? Actor);

// Exposed so the test host (WebApplicationFactory) can reference the entry assembly.
public partial class Program { }
