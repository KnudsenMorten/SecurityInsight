using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Jobs;
using SI.Management.Web.Links;
using SI.Management.Web.Data;
using SI.Management.Web.Estate;
using SI.Management.Web.Settings;
using SI.Management.Web.Timing;

var builder = WebApplication.CreateBuilder(args);

// ---- Sign-in: Entra (Microsoft.Identity.Web), app roles SuperAdmin + Admin + Viewer (Reader) + Wallboard ----------
var azureAd = builder.Configuration.GetSection("AzureAd");
// CR7 (framework 12.11g): behind the ONE shared sign-in front (FRAMEWORK/signin-front) the front signs the user in and this
// app verifies the front's token on every request, listening on 127.0.0.1 only (Auth/SigninFront.cs). OFF (the default):
// the in-app sign-in below, exactly as before.
var signinFront = SigninFront.IsEnabled(builder.Configuration);
if (signinFront)
{
    builder.WebHost.UseUrls(SigninFront.ListenUrl(builder.Configuration));
    SigninFront.AddSigninFrontAuthentication(builder.Services, builder.Configuration);
    // the guided mail setup's delegated Exchange token needs the in-app sign-in: behind the front there is none, so the
    // page hands over setup\Set-SIMail.ps1 (DelegatedExchangeTokenSource finds no token acquisition)
}
else
{
var webApp = builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(azureAd);
// The guided mail setup (Settings > E-mail + links > Set up mail) calls Exchange Online with the signed-in admin's
// delegated token. Only when the app registration's credentials are configured; the Exchange scope is requested
// incrementally on that page alone (no initial scopes: nobody else is asked to consent). Not configured: the app starts
// exactly as before and the page hands over setup\Set-SIMail.ps1 instead.
if (SI.Management.Web.Settings.DelegatedExchangeTokenSource.CanAcquire(azureAd))
    webApp.EnableTokenAcquisitionToCallDownstreamApi(Array.Empty<string>()).AddInMemoryTokenCaches();
}
// Claims exactly as Entra sends them: app roles in `roles`, the UPN in `preferred_username` (no inbound remapping),
// so the policies below and the name written to cfg.ChangeLog do not depend on a claim-type translation table.
// PostConfigure, not Configure, and on the token handler too: Microsoft.Identity.Web configures the handler after an
// ordinary Configure, so `roles` still arrived remapped to the long role claim type and an assigned Admin was shown
// "No role" (live 2026-10-04; EntraRoleClaimTests reproduces the real Entra path).
builder.Services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, o =>
{
    o.MapInboundClaims = false;
    if (o.TokenHandler is Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler jwt) jwt.MapInboundClaims = false;
#pragma warning disable CS0618 // the legacy validator, should anything switch it back on
    if (o.SecurityTokenValidator is System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler legacy) legacy.MapInboundClaims = false;
#pragma warning restore CS0618
    o.TokenValidationParameters.RoleClaimType = "roles";
    o.TokenValidationParameters.NameClaimType = "preferred_username";
    // the session is the app's own fixed 8 h (below), never the token's lifetime; PKCE whenever the code flow is used
    // (the code flow is on when the sign-in credential -- the managed identity's federated credential -- is configured)
    o.UseTokenLifetime = false;
    o.UsePkce = true;
});
// The in-app sign-in's session = the shared front's: SigninFront.SessionHours (8 h) from the sign-in, FIXED (never slid by
// activity), so Entra -- Conditional Access sign-in frequency, a disabled account -- is asked again at least every 8 h.
builder.Services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, o =>
{
    o.AccessDeniedPath = "/Denied";
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.HttpOnly = true;
    o.ExpireTimeSpan = SigninFront.Session;
    o.SlidingExpiration = false;
});
// Headless browser tests only: Development + SIWeb_E2EAuth=true. The setting outside Development stops the start.
E2EAuth.AddIfEnabled(builder.Services, builder.Configuration, builder.Environment);

// ---- Roles (#253): Reader < Delegated < Admin < SuperAdmin, as in PIM Manager. The Entra app role gates sign-in; the
// portal mapping (Admin > Access, cfg.AccessAssignment) raises a signed-in user on top. The effective role and scopes are
// resolved on every request (the mapping is cached for seconds) and every page and handler checks them server-side.
builder.Services.Configure<AccessOptions>(builder.Configuration.GetSection(AccessOptions.Section));
var access = builder.Configuration.GetSection(AccessOptions.Section).Get<AccessOptions>() ?? new AccessOptions();
builder.Services.AddSingleton<IAccessStore, SqlAccessStore>();
builder.Services.AddSingleton<IAccessScope, AccessScopeService>();
if (access.GraphLookup)
{
    builder.Services.AddHttpClient<GraphDirectory>();
    builder.Services.AddSingleton<IGroupMembershipSource>(sp => sp.GetRequiredService<GraphDirectory>());
    builder.Services.AddSingleton<IDirectoryNames>(sp => sp.GetRequiredService<GraphDirectory>());
}
else
{
    builder.Services.AddSingleton<NoDirectoryLookup>();
    builder.Services.AddSingleton<IGroupMembershipSource>(sp => sp.GetRequiredService<NoDirectoryLookup>());
    builder.Services.AddSingleton<IDirectoryNames>(sp => sp.GetRequiredService<NoDirectoryLookup>());
}
builder.Services.AddTransient<IClaimsTransformation, AccessClaimsTransformation>();

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy(Policies.Admin, p => p.RequireAuthenticatedUser().RequireAssertion(ctx => ctx.User.IsAdmin()));
    o.AddPolicy(Policies.SuperAdmin, p => p.RequireAuthenticatedUser().RequireAssertion(ctx => ctx.User.IsSuperAdmin()));
    // Review & commit: whoever may stage (Delegated inside their scopes, Admin, SuperAdmin) -- each change re-checked on commit
    o.AddPolicy(Policies.Change, p => p.RequireAuthenticatedUser().RequireAssertion(ctx => ctx.User.MayChange()));
    // Reader and up -- or a magic-link session for exactly the page it was issued for (magic links are OFF by default)
    o.AddPolicy(Policies.Management, p => p.RequireAuthenticatedUser().RequireAssertion(ctx => ctx.MayRead()));
    o.AddPolicy(Policies.Wallboard, p => p.RequireAuthenticatedUser().RequireAssertion(ctx => ctx.MayRead() || ctx.User.IsInRole(Roles.Wallboard)));
    // the department pages (#254): a reader, or a person of a department (who then sees only their departments)
    o.AddPolicy(SI.Management.Web.Departments.DepartmentPolicy.Name, p => p.RequireAuthenticatedUser().AddRequirements(new SI.Management.Web.Departments.DepartmentAccessRequirement()));
    // Everything not marked otherwise needs a signed-in user WITH SOME ACCESS (#765: the enterprise app no longer requires
    // an assignment, so any person of the directory can sign in -- and sees nothing until SecurityInsight gives them a role)
    // -- including the static files, which are served AFTER the authorization middleware below (a person with no role gets
    // the style sheet and the brand only). The one anonymous endpoints are /healthz and the magic-link redeemer + request
    // page (the redeemer checks its own single-use token).
    o.AddPolicy(Policies.SignedIn, p => p.RequireAuthenticatedUser());
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().AddRequirements(new AnyAccessRequirement()).Build();
    o.DefaultPolicy = o.FallbackPolicy;
});
builder.Services.AddSingleton<IAuthorizationHandler, AnyAccessHandler>();
// #765: the Entra app role holders carried over into SecurityInsight's access table at start (people who never sign in,
// and groups) -- once, through the same idempotent statement the sign-in uses; only when the directory lookup is on
builder.Services.AddHostedService<AccessCarryOverAtStart>();

builder.Services.AddRazorPages(o =>
{
    // Admin for the whole folder -- except the audit trail (#260), which a Delegated user may open for their scope
    o.Conventions.AddFolderApplicationModelConvention("/Admin", m =>
    {
        if (!string.Equals(m.ViewEnginePath, "/Admin/History", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(m.ViewEnginePath, "/Admin/Guards", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(m.ViewEnginePath, "/Admin/Verification", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(m.ViewEnginePath, "/Admin/DataHealth", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(m.ViewEnginePath, "/Admin/Performance", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(m.ViewEnginePath, "/Admin/DataQuality", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(m.ViewEnginePath, "/Admin/QuerySplitting", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(m.ViewEnginePath, "/Admin/RunHealth/Reports", StringComparison.OrdinalIgnoreCase))
            m.EndpointMetadata.Add(new AuthorizeAttribute(Policies.Admin));
    });
    o.Conventions.AuthorizePage("/Admin/History", Policies.Change);
    // #822: "Set value" of a secret -- SuperAdmin only (the handler checks it again)
    o.Conventions.AuthorizePage("/Admin/Secrets/Set", Policies.SuperAdmin);
    // #277: the Guards view (Operations > Guards (safety checks)) -- readers may see what the safety checks held
    o.Conventions.AuthorizePage("/Admin/Guards", Policies.Management);
    // the verification service's data-collection gaps (Operations > Verification): readers see them; deciding is Admin (the handlers check it)
    o.Conventions.AuthorizePage("/Admin/Verification", Policies.Management);
    // CR2 (#656): the data health check (Configuration > Connectors > Data-health hold) -- readers see it; letting a channel through is SuperAdmin (its handlers check it)
    o.Conventions.AuthorizePage("/Admin/DataHealth", Policies.Management);
    // #757: Operations > Performance -- readers see it; asking for a size is Admin, starting the updater SuperAdmin (its handlers check it)
    o.Conventions.AuthorizePage("/Admin/Performance", Policies.Management);
    // #577: the data-quality warnings (Operations > Data quality) -- readers see them; Re-run from here is Admin (its handler checks it, like Admin > Jobs)
    o.Conventions.AuthorizePage("/Admin/DataQuality", Policies.Management);
    // #640: the Risk Analysis bucket counts (Operations > Risk Analysis query splitting) -- readers see them; a reset is Admin (its handler checks it)
    o.Conventions.AuthorizePage("/Admin/QuerySplitting", Policies.Management);
    // #641: every report of a Risk Analysis run with its verdict -- readers may view it (the run's report to Invardia links here)
    o.Conventions.AuthorizePage("/Admin/RunHealth/Reports", Policies.Management);
    // role and scope assignment: SuperAdmin (on top of the folder's Admin)
    o.Conventions.AuthorizePage("/Admin/Access", Policies.SuperAdmin);
    // the guided mail setup (Exchange RBAC for Applications / SMTP relay): SuperAdmin
    o.Conventions.AuthorizePage("/Admin/Settings/MailSetup", Policies.SuperAdmin);
    o.Conventions.AuthorizeFolder("/Changes", Policies.Change);
    o.Conventions.AuthorizeFolder("/Management", Policies.Management);
    o.Conventions.AuthorizeFolder("/Findings", Policies.Management);
    // the fourteen collection views: Admin or Viewer, like Findings (the wall board account sees none of them)
    o.Conventions.AuthorizeFolder("/Collection", Policies.Management);
    o.Conventions.AuthorizeFolder("/Tiers", Policies.Management);
    // the CIs and the records per source (V3-DATA-MODEL 2.13): every reader; the tenant default columns are Admin (checked inside)
    o.Conventions.AuthorizeFolder("/Cis", Policies.Management);
    o.Conventions.AuthorizeFolder("/Records", Policies.Management);
    // #583 Risks > Summary (the RiskAnalysis_Summary workbook's rows, grouped by tier): every reader
    o.Conventions.AuthorizeFolder("/Summary", Policies.Management);
    // #636 Security recommendations > Summary and the Remediations menu: every reader
    o.Conventions.AuthorizeFolder("/Recommendations", Policies.Management);
    o.Conventions.AuthorizeFolder("/Remediations", Policies.Management);
    // the CMDB pages: every reader sees them; every change on them checks Admin itself (and the CMDB source)
    o.Conventions.AuthorizeFolder("/Cmdb", Policies.Management);
    o.Conventions.AuthorizeFolder("/Departments", SI.Management.Web.Departments.DepartmentPolicy.Name);
    // the Unassigned queue spans every department: readers only (on top of the folder's policy)
    o.Conventions.AuthorizePage("/Departments/Unassigned", Policies.Management);
    // #265: follow-up tasks -- readers and the department people (advisors, owners, sign-in link sessions) see their own;
    // what each one sees and may change is decided per task by FindingTaskService (Admin > All tasks is under /Admin)
    o.Conventions.AuthorizeFolder("/Tasks", SI.Management.Web.Departments.DepartmentPolicy.Name);
    // #272: the ONE endpoint of the shared action bar -- readers and the department people; each action decides per finding
    o.Conventions.AuthorizeFolder("/Actions", SI.Management.Web.Departments.DepartmentPolicy.Name);
    // the column chooser of every data view saves here (a person's own layout; the tenant default is Admin, checked inside)
    o.Conventions.AuthorizePage("/Columns", SI.Management.Web.Departments.DepartmentPolicy.Name);
    o.Conventions.AuthorizeFolder("/Templates", Policies.Management);
    // #266 the risk index: readers see it (read-only, export); every change on it checks Admin itself
    o.Conventions.AuthorizeFolder("/RiskIndex", Policies.Management);
    // #527 (4) Risk factors: readers see them; every change checks Admin itself
    o.Conventions.AuthorizeFolder("/RiskFactors", Policies.Management);
    // #462 Rule packs: readers see them; every change checks Admin itself (the CI overrides page is under /Cis)
    o.Conventions.AuthorizeFolder("/RulePacks", Policies.Management);
    // #274 Reports: readers see it read-only; every change on it checks Admin itself
    o.Conventions.AuthorizeFolder("/Reports", Policies.Management);
    // owner 2026-10-19 ("one for reports and one for connectors"): the connectors' fields and scope -- the same rule
    o.Conventions.AuthorizeFolder("/Connectors", Policies.Management);
    // #275 L4: profiling rules, asset tagging, schema overlays -- readers see them; every change checks Admin itself
    o.Conventions.AuthorizeFolder("/Rules", Policies.Management);
    o.Conventions.AuthorizeFolder("/AssetTagging", Policies.Management);
    o.Conventions.AuthorizeFolder("/SchemaOverlay", Policies.Management);
    // #252 exemptions: Admin or Viewer request; who may decide or review is checked per domain by ExemptionWorkflow
    o.Conventions.AuthorizeFolder("/Exemptions", Policies.Management);
    o.Conventions.AuthorizePage("/Chat", Policies.Management);
    o.Conventions.AuthorizePage("/Help", Policies.Management);
    // #285: the global search of the header (assets, findings, CVEs, people, reports) -- under each reader's visibility
    o.Conventions.AuthorizePage("/Search", Policies.Management);
    o.Conventions.AuthorizePage("/Wallboard", Policies.Wallboard);
    // the landing page sends each role to its own start page (Wallboard -> the wall board; no role -> /NoAccess)
    o.Conventions.AuthorizePage("/Index", Policies.SignedIn);
    // #765: the pages a signed-in person WITHOUT a SecurityInsight role still reaches (nothing else)
    o.Conventions.AuthorizePage("/NoAccess", Policies.SignedIn);
    o.Conventions.AuthorizePage("/Denied", Policies.SignedIn);
    o.Conventions.AuthorizePage("/Error", Policies.SignedIn);
    // The link redeemer (it checks its own single-use token) -- with or without the sign-in front. Behind the front these two
    // are EXACTLY the front's anonymous paths (SigninFront.AnonymousPaths = its SIGNIN_ANONYMOUS_PATHS, CR7 Option A); every
    // other route needs the front's token, and a redeemed link browses under /MagicLink/s/ with its own session (LinkArea).
    o.Conventions.AllowAnonymousToPage("/MagicLink");
    // #258: "no work account here? mail me a sign-in link" -- answers the same whatever address is typed
    o.Conventions.AllowAnonymousToPage("/MagicLinkRequest");
}).AddMvcOptions(o => o.Filters.AddService<SI.Management.Web.Exemptions.ExemptedPageFilter>())
// THE audit trail (#260, AUDIT-1): one event row per mutating request / export / sign-in event -- success, refusal or
// error -- written by a global page filter; requests the role framework refuses before a handler are written by the
// authorization result handler below.
.AddMvcOptions(m => m.Filters.Add<SI.Management.Web.Audit.AuditPageFilter>())
// ONE WEB APP, BOTH VERSIONS (owner 2026-10-18): a paid page or handler without a Pro licence is refused HERE, server side, on
// every request (Licensing/ProFeatures.cs) -- after the audit filter, so a refused change is on the audit trail as refused.
.AddMvcOptions(m => m.Filters.Add<SI.Management.Web.Licensing.ProFeaturePageFilter>());
builder.Services.AddSingleton(_ => SI.Management.Web.Audit.AuditActions.Default);
builder.Services.AddSingleton<SI.Management.Web.Audit.AuditHealth>();
builder.Services.AddSingleton<SI.Management.Web.Audit.IAuditWriter, SI.Management.Web.Audit.SqlAuditWriter>();
// CR8 step 2 (observe only): each change with the person's signed token, verified by the pipeline runner -- nothing refused yet
builder.Services.AddSingleton<SI.Management.Web.Audit.ISignedRequestWriter, SI.Management.Web.Audit.SqlSignedRequestWriter>();
// #302 (AUDIT-1.1): who asked for a change a job carries out -- recorded at commit, read by the jobs' audit writer
builder.Services.AddSingleton<SI.Management.Web.Audit.IChangeAttributionWriter, SI.Management.Web.Audit.SqlChangeAttributionWriter>();
builder.Services.AddSingleton<SI.Management.Web.Audit.AuditTrailReader>();
// #277: the guard events -- the Guards view's reads and the web app's own guard writes (mailed by the mail job)
builder.Services.AddSingleton(_ => SI.Management.Web.Guards.GuardCatalog.Default);
builder.Services.AddSingleton<SI.Management.Web.Guards.IGuardEventStore, SI.Management.Web.Guards.SqlGuardEventStore>();
// #414: the guard switches (Settings > Guards) -- a guard switched off writes no event
builder.Services.AddSingleton<SI.Management.Web.Guards.GuardSwitches>();
builder.Services.AddSingleton<SI.Management.Web.Guards.GuardEventWriter>();
// a held vulnerability close set, released once by an Admin from Operations > Guards (operator decision 2026-10-04)
builder.Services.AddSingleton<SI.Management.Web.Guards.IGuardReleaseStore, SI.Management.Web.Guards.SqlGuardReleaseStore>();
// a held Risk Analysis collection an Admin released is loaded once and MARKED PARTIAL: the badge wherever it is shown
builder.Services.AddSingleton<SI.Management.Web.Collection.IPartialCollections, SI.Management.Web.Collection.SqlPartialCollections>();
// a source whose newest collection did not complete: the banner on every page, the note on a collection, an export's line
builder.Services.AddSingleton<SI.Management.Web.Collection.ISourceNotes, SI.Management.Web.Collection.SqlSourceNotes>();
// a data sync is running: one calm line on every page ("the pages show the previous data until it is done")
builder.Services.AddSingleton<SI.Management.Web.Collection.ISyncNotices, SI.Management.Web.Collection.SqlSyncNotices>();
// ONE TRUSTED RUN (owner 2026-10-19): which run every page shows -- "Data from the run of ... · a newer run is in progress"
builder.Services.AddSingleton<SI.Management.Web.Collection.IPublishedRunNotices, SI.Management.Web.Collection.SqlPublishedRunNotices>();
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, SI.Management.Web.Audit.AuditAuthorizationResultHandler>();
// #264: a page that shows exempted findings reads under its surface's setting, overridden by the view's tick
builder.Services.AddSingleton<SI.Management.Web.Exemptions.IExemptedSchema, SI.Management.Web.Exemptions.SqlExemptedSchema>();
builder.Services.AddSingleton<SI.Management.Web.Exemptions.ExemptedPageFilter>();

// Container Apps terminates TLS at its ingress: trust its X-Forwarded-* so the sign-in redirect URI is https.
// Behind the sign-in front (127.0.0.1 only) the front sets X-Forwarded-Proto / -Host for the address the user sees.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | (signinFront ? ForwardedHeaders.XForwardedHost : ForwardedHeaders.None);
    o.KnownNetworks.Clear();
    o.KnownProxies.Clear();
});

// ---- Data + estate: SI.Management.Core registers the ONE credential (section "Identity": managed identity hosted,
// a LocalMachine\My certificate locally -- never a secret), the estate query layer ("Estate": workspace + the one Pro
// database) and the chat ("Chat": the customer's Azure OpenAI). The Settings / Close-loop pages reach the same Pro
// database through ISqlExecutor with the same credential.
builder.Services.AddSecurityInsightEstate(builder.Configuration);
var estate = builder.Configuration.GetSection(EstateOptions.Section).Get<EstateOptions>() ?? new EstateOptions();
var chat = builder.Configuration.GetSection(ChatOptions.Section).Get<ChatOptions>() ?? new ChatOptions();
if (string.IsNullOrWhiteSpace(estate.WorkspaceId))
{
    // no workspace: every dashboard says "not configured" rather than failing or inventing data
    builder.Services.RemoveAll<IEstateQueries>();
    builder.Services.AddSingleton<IEstateQueries, NotConfiguredEstateQueries>();
}
else
{
    // a failing query renders a notice on its page, never an error page
    var inner = builder.Services.Last(d => d.ServiceType == typeof(IEstateQueries));
    builder.Services.Remove(inner);
    builder.Services.AddSingleton<IEstateQueries>(sp => new ResilientEstateQueries(
        (IEstateQueries)(inner.ImplementationFactory?.Invoke(sp) ?? inner.ImplementationInstance ?? ActivatorUtilities.CreateInstance(sp, inner.ImplementationType!)),
        sp.GetRequiredService<ILogger<ResilientEstateQueries>>()));
}
if (string.IsNullOrWhiteSpace(chat.Endpoint) || string.IsNullOrWhiteSpace(chat.Deployment))
{
    builder.Services.RemoveAll<IChatService>();
    builder.Services.AddSingleton<IChatService, NotConfiguredChatService>();
}
// ONE TRUSTED RUN FOR THE CIs (owner 2026-10-19): every read of the CIs and the assets is of their published copies once
// one is published -- the CI build of the run in progress is never shown (DataAccess/PublishedCopyExecutor.cs)
if (AzureSqlExecutor.IsConfigured(estate))
{
    builder.Services.AddSingleton<AzureSqlExecutor>();
    builder.Services.AddSingleton<ISqlExecutor>(sp => new PublishedCopyExecutor(sp.GetRequiredService<AzureSqlExecutor>()));
}
else builder.Services.AddSingleton<ISqlExecutor, NotConfiguredSqlExecutor>();
// #345: the sign-in cookie's and the forms' antiforgery keys are SHARED in the Pro database (cfg.WebKeyRing) -- on the
// container's disk every new revision (and the second replica) had its own, so a deploy signed every open page out and
// refused its next save. One application name, so every revision reads the same keys. No database: the default (in memory).
builder.Services.AddDataProtection().SetApplicationName("SecurityInsight Pro");
if (AzureSqlExecutor.IsConfigured(estate))
    builder.Services.AddOptions<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>()
        .Configure<ISqlExecutor, ILoggerFactory>((o, sql, lf) => o.XmlRepository = new SqlKeyRing(sql, lf.CreateLogger<SqlKeyRing>()));

builder.Services.AddSingleton(sp =>
{
    var path = builder.Configuration["Settings:CatalogPath"];
    return SettingsCatalog.Load(string.IsNullOrWhiteSpace(path) ? SettingsCatalog.DefaultPath(builder.Environment.ContentRootPath) : path).WithWebSettings();
});
builder.Services.AddSingleton<ISettingsStoreReader, SqlSettingsReader>();
builder.Services.AddSingleton<SettingsWriter>();
builder.Services.AddSingleton<SettingsSaver>();   // #446: the one save of a set of settings (Settings cards and Get Started steps)
builder.Services.AddSingleton<ICloseLoopReader, SqlCloseLoopReader>();

// ---- Pro data backend (sidata.*), staging -> review -> commit, jobs, connectors, links ---------------------------
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSingleton<IProSql, ExecutorProSql>();
// What the views over the CURRENT data read is kept per DATA VERSION: the data sync's mark plus a few narrow figures of the
// tables they read (asked at most every few seconds). A page of All CIs, the findings per CI, the findings per finding key,
// the records, the correlation figures and trend, the findings browser's pivot and the tier-0 ranking is read once until
// new data is stored -- never kept by time alone, an export never kept.
builder.Services.AddSingleton<IDataVersion>(sp => new DataVersion(sp.GetRequiredService<IProSql>()));
builder.Services.AddSingleton<ViewResultCache>();
builder.Services.AddSingleton<IProDataQueries>(sp => new ProDataQueries(sp.GetRequiredService<IProSql>(), estate.VulnerabilitySource) { ViewsCache = sp.GetService<ViewResultCache>() });
// #288: the Risk Analysis executive view -- what each report's mail showed (sidata.RiskExecView), never recomputed
builder.Services.AddSingleton<IRiskExecViews>(sp => new SqlRiskExecViews(sp.GetRequiredService<IProSql>()));
builder.Services.AddSingleton<SI.Management.Web.RiskExec.ExecViewLoader>();
// #291: the management summary report -- definitions + outbox (cfg.MgmtReport / cfg.ReportMail), its composer and
// sender, and the schedule's 5-minute pass (a period is claimed before it is queued: never sent twice)
builder.Services.TryAddSingleton(TimeProvider.System);
builder.Services.AddSingleton<SI.Management.Web.MgmtReports.IMgmtReportStore, SI.Management.Web.MgmtReports.SqlMgmtReportStore>();
builder.Services.AddSingleton<SI.Management.Web.MgmtReports.MgmtReportSender>();
builder.Services.AddHostedService<SI.Management.Web.MgmtReports.MgmtReportScheduler>();
// The collection views (#241): read-only SQL over the Pro database, cached per collection (a complete collection never
// changes). Never Log Analytics.
builder.Services.AddSingleton<ICollectionViews>(sp => new SI.Management.Web.Collection.CachedCollectionViews(
    new CollectionViews(sp.GetRequiredService<IProSql>(), estate.VulnerabilitySource)));
// #360: the weighted risk page's saved pivot views (cfg.PivotView): personal, or shared by an Admin
builder.Services.AddSingleton<SI.Management.Web.Collection.IPivotViewStore, SI.Management.Web.Collection.SqlPivotViewStore>();
// Correlation evidence per CI and the correlation-quality report: read-only SQL over what the data sync computed.
builder.Services.AddSingleton<ICorrelationViews>(sp => new CorrelationViews(sp.GetRequiredService<IProSql>(), cache: sp.GetService<ViewResultCache>()));
// #408: the full asset metadata per CI (sidata.AssetMetadata, filled by the data sync when SI_AssetProperties = full): read-only SQL.
builder.Services.AddSingleton<IAssetMetadataViews>(sp => new AssetMetadataViews(sp.GetRequiredService<IProSql>()));
// "Export all columns" on the CI pages: every CI field and the full details per source, read in batches (read-only SQL).
builder.Services.AddSingleton<ICiFullExportViews>(sp => new CiFullExportViews(sp.GetRequiredService<IProSql>()));
// Every column on every data view: the CI id, CI fields, identifier values, linked objects, source properties and finding
// fields -- read late, for the rows shown or exported only, by their CI key (read-only SQL; the chooser's lists as the data
// sync stored them, kept while they stand still; a read that fails is logged and the chooser offers the columns without them).
builder.Services.AddSingleton<IDataColumnViews>(sp =>
{
    var log = sp.GetRequiredService<ILogger<DataColumnViews>>();
    return new DataColumnViews(sp.GetRequiredService<IProSql>())
    {
        OnReadFailed = ex => log.LogWarning(ex, "the column chooser's lists could not be read; the chooser offers the columns without them for now"),
    };
});
// The CIs, one CI and the records per source (V3-DATA-MODEL 2.13): read-only SQL over the v3 tables the data sync fills
// (sidata.Ci / CiLink / CiFinding / CiDaily / CiRecord); absent tables read as "not loaded yet". The grid's column
// layouts (cfg.ColumnLayout): the tenant default and each person's own.
// Which tables exist and the CIs' state -- asked by every CI view before its page -- are kept for minutes / seconds.
builder.Services.AddSingleton<ICiViews>(sp => new CiViews(sp.GetRequiredService<IProSql>(), cache: sp.GetService<ViewResultCache>(), keepProbes: true));
// The CI graph (#493 / #494 / #496): a CI's services, relations, findings with their lifecycle and changes; a service's CIs
builder.Services.AddSingleton<ICiGraphViews>(sp => new CiGraphViews(sp.GetRequiredService<IProSql>()));
// #858 active devices not onboarded in Defender (MDE device discovery + Azure machines without the agent), per status
builder.Services.AddSingleton<INotOnboardedViews>(sp => new NotOnboardedViews(sp.GetRequiredService<IProSql>(), sp.GetRequiredService<ICiViews>()));
builder.Services.AddSingleton<SI.Management.Web.Cis.IColumnLayoutStore, SI.Management.Web.Cis.SqlColumnLayoutStore>();
// Asset responsibility (#254): departments, their people, rules and overrides (cfg.*), the department pages' reads
// (precomputed by the data sync), and the department scope every data query asks for.
builder.Services.AddSingleton<SI.Management.Web.Departments.DepartmentRepository>();
builder.Services.AddSingleton<IDepartmentViews>(sp => new DepartmentViews(sp.GetRequiredService<IProSql>()));
// #636: Security recommendations > Summary, the Remediations pages and the key figures of the Executive overview / report
builder.Services.AddSingleton<IRecommendationViews>(sp => new SqlRecommendationViews(sp.GetRequiredService<IProSql>()));
builder.Services.AddSingleton<SI.Management.Web.Departments.IDepartmentScopeResolver, SI.Management.Web.Departments.MembershipDepartmentScope>();
builder.Services.AddSingleton<IAuthorizationHandler, SI.Management.Web.Departments.DepartmentAccessHandler>();
// #335: the people fields typed on the department pages, and who approves what (technical / business approvers)
builder.Services.AddSingleton<SI.Management.Web.Departments.DepartmentPeopleResolver>();
builder.Services.AddSingleton<SI.Management.Web.Departments.DepartmentApprovers>();
builder.Services.AddSingleton<SI.Management.Web.Exemptions.IDepartmentDeciders>(sp => sp.GetRequiredService<SI.Management.Web.Departments.DepartmentApprovers>());
// #254 phase 2 + 3: the governance log per finding, the remediation flows, the vendor-escalation outbox (cfg.*)
builder.Services.AddSingleton<SI.Management.Web.Departments.GovernanceRepository>();
builder.Services.AddSingleton<SI.Management.Web.Departments.GovernanceService>();
builder.Services.AddSingleton<ExemptionRepository>();
// #252: exemptions as a governed flow -- domain owners and approvers, request -> approve, review; mails via the outbox
builder.Services.AddSingleton<SI.Management.Web.Exemptions.ExemptionSettings>();
builder.Services.AddSingleton<SI.Management.Web.Exemptions.IExemptionStore, SI.Management.Web.Exemptions.SqlExemptionStore>();
builder.Services.AddSingleton<SI.Management.Web.Exemptions.IExemptionMailer, SI.Management.Web.Exemptions.OutboxExemptionMailer>();
builder.Services.AddSingleton<SI.Management.Web.Exemptions.ExemptionWorkflow>();
builder.Services.AddSingleton<DocumentRepository>();
builder.Services.AddSingleton<ItemOverrideRepository>();
builder.Services.AddSingleton<RiskFactorStore>();
// #462 the CI rule packs (data model in SQL) and the manual CI overrides (sidata.CiOverride, through Review & commit)
builder.Services.AddSingleton<RulePackStore>();
builder.Services.AddSingleton<CiOverrideStore>();
builder.Services.AddSingleton<CiOverrideChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<CiOverrideChanges>());
builder.Services.AddSingleton<TemplateConformance>();
builder.Services.AddSingleton<ConnectorRepository>();
// The deviation report (Admin > Deviations): read-only; CSV and Excel export.
builder.Services.AddSingleton<SI.Management.Web.Deviations.IDeviationSource, SI.Management.Web.Deviations.SqlDeviationSource>();
builder.Services.AddSingleton<SI.Management.Web.Deviations.IDeviationWorkbookWriter, SI.Management.Web.Deviations.XlsxDeviationWorkbookWriter>();
builder.Services.AddSingleton<TemplateReleases>();
// framework PENDING-1: what waits for a person and blocks work -- counted on every page load for the menu badges
builder.Services.AddSingleton<SI.Management.Web.Navigation.IBlockingItemSource, SI.Management.Web.Navigation.SqlBlockingItemSource>();
// the counts the Assets (CIs) tabs carry (All CIs / At risk), from stored, cached counts (owner 2026-10-19)
builder.Services.AddSingleton<SI.Management.Web.Navigation.TabCounts>();
// the lifecycle numbers every view's "What you're looking at" line says (owner 2026-10-19)
builder.Services.AddSingleton<SI.Management.Core.ProData.ICiLifecycleRulesReader, SI.Management.Web.Pages.CiLifecycleRulesStore>();
builder.Services.AddSingleton<LicenceRequestReader>();
// the installed licence as the updater verified it (cfg.InstallState 'Licence') -- the Licence card on the Settings page
builder.Services.AddSingleton<InstalledLicenceReader>();
// the paid features of the web app follow the installed licence (deny by default: no Pro licence recorded = not Pro).
// (2026-10-28: this registration had been merged INTO the comment line above -- the real app registered no IProLicence and
// every page failed with "Unable to resolve service for type IProLicence"; the unit tests' host registers a fake, so only
// E2EAuthTests, which runs the real app, saw it. Guarded by EditionBrandTests.The_real_app_registers_the_licence_check.)
builder.Services.AddSingleton<SI.Management.Web.Licensing.IProLicence, SI.Management.Web.Licensing.InstalledProLicence>();
// LICENCE-DIMENSION: Pro Business / Pro Enterprise and the devices a Business licence covers (header, banner, Licence card)
builder.Services.AddSingleton<ILicenceUsageSource, LicenceUsageReader>();
builder.Services.AddSingleton<UpdateStateReader>();
// CR3 (#657): the components of the installed code, Testing / Stable (cfg.ReleaseScope; Settings > Updates)
builder.Services.AddSingleton<ReleaseComponentsReader>();
builder.Services.AddSingleton<DimensionMappingPreview>();   // #772 the sub-CI / OS family mapping page's preview
builder.Services.AddSingleton<SI.Management.Web.Settings.PatchCycleSettings>();   // #772 the patch cycle's threshold in words (a view's scope line)
// Settings > Updates: claim the install key again (one request row, written through cfg.InstallKeyClaimAgainRequest)
builder.Services.AddSingleton<InstallKeyClaimAgain>();
// CR4 (#654): the guard mode -- the stricter period after a release that changed engine code (header, Guards, halved limits)
builder.Services.AddSingleton<SI.Management.Web.Guards.GuardModeReader>();
builder.Services.AddSingleton<InstallRingReader>();
// owner 2026-10-19: the header shows the INSTALLED release (cfg.InstallState EngineFingerprint), not the image's build number
builder.Services.AddSingleton<SI.Management.Web.Changes.InstalledRelease>();
builder.Services.AddSingleton<InstallTenantReader>();   // the tenant's name as setup read it from Entra ID (header TENANT)
builder.Services.AddSingleton<IStagingStore, CacheStagingStore>();
// The CMDB (#256): its store and the service map's staged links. Services per collection are read through the data
// sync's one resolver (sidata.ServiceMember), which the CMDB plugs into as its authoritative source.
builder.Services.AddSingleton<SI.Management.Web.Cmdb.ICmdbStore, SI.Management.Web.Cmdb.SqlCmdbStore>();
// #271: the SQL CMDB connector's CI table, read only (the job writes it)
builder.Services.AddSingleton<SI.Management.Web.Cmdb.ICmdbSqlSyncReader, SI.Management.Web.Cmdb.SqlCmdbSqlSyncReader>();
// #406: the assets SecurityInsight no longer sees (cmdbsync.AssetLifecycle) -- read, and an Admin's early retirement
builder.Services.AddSingleton<SI.Management.Web.Cmdb.IAssetLifecycleStore, SI.Management.Web.Cmdb.SqlAssetLifecycleStore>();
// V3-DATA-MODEL 2.11: the verification service's gaps, check results and the decisions on them (cfg.Verification*)
builder.Services.AddSingleton<SI.Management.Web.Verification.IVerificationStore, SI.Management.Web.Verification.SqlVerificationStore>();
// CR2 (#656): the data health state (header) and Configuration > Connectors > Data-health hold
builder.Services.AddSingleton<SI.Management.Web.DataHealth.IDataHealthStore, SI.Management.Web.DataHealth.SqlDataHealthStore>();
// #757: Operations > Performance -- runs, collection state, the heartbeat's hourly load samples (cfg.PerfSample); SQL only
builder.Services.AddSingleton<SI.Management.Web.Performance.IPerformanceStore, SI.Management.Web.Performance.SqlPerformanceStore>();
// #640: the Risk Analysis bucket counts and their one-time reset (staged through Review & commit)
builder.Services.AddSingleton<SI.Management.Web.QuerySplitting.IQuerySplittingStore, SI.Management.Web.QuerySplitting.SqlQuerySplittingStore>();
builder.Services.AddSingleton<SI.Management.Web.RunReports.IRunReportsStore, SI.Management.Web.RunReports.SqlRunReportsStore>();
// #902 (5): an Admin accepts a source that went silent as empty for good, per report (staged through Review & commit)
builder.Services.AddSingleton<SI.Management.Web.RunReports.ISourceAcceptStore, SI.Management.Web.RunReports.SqlSourceAcceptStore>();
builder.Services.AddSingleton<SI.Management.Web.RunReports.SourceAcceptChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SI.Management.Web.RunReports.SourceAcceptChanges>());
// the detailed Excel workbook's size (Settings: the switch is greyed out above what a workbook holds here)
builder.Services.AddSingleton<SI.Management.Web.Settings.IDetailedWorkbookSize, SI.Management.Web.Settings.SqlDetailedWorkbookSize>();
builder.Services.AddSingleton<SI.Management.Web.QuerySplitting.QuerySplittingChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SI.Management.Web.QuerySplitting.QuerySplittingChanges>());
// #577: the data-quality fingerprint per pipeline run and its anomalies (sidata.DataQuality*), read-only
// (a run's rows never change once written: the picked run's detail is kept per data version)
builder.Services.AddSingleton<SI.Management.Web.DataQuality.IDataQualityStore>(sp =>
    new SI.Management.Web.DataQuality.SqlDataQualityStore(sp.GetRequiredService<ISqlExecutor>(), sp.GetService<ViewResultCache>()));
// #583 Risks > Summary: the Risk Analysis Summary rows the data sync loads (sidata.SummaryLoad / SummaryRow / SummaryAsset), read-only
builder.Services.AddSingleton<SI.Management.Web.Summary.ISummaryReportStore, SI.Management.Web.Summary.SqlSummaryReportStore>();
// #636: Risks > Summary as the stored groupings of the Detailed findings (sidata.SummaryGroup, written by the data sync)
builder.Services.AddSingleton<SI.Management.Web.Summary.ISummaryGroupsStore, SI.Management.Web.Summary.SqlSummaryGroupsStore>();
// the ServiceNow test pack's "Preview with your data": the first rows of the Pro database's hand-off views, read only
builder.Services.AddSingleton<SI.Management.Web.Cmdb.IServiceNowPreview, SI.Management.Web.Cmdb.SqlServiceNowPreview>();
builder.Services.AddSingleton<SI.Management.Web.Cmdb.CmdbChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SI.Management.Web.Cmdb.CmdbChanges>());
// #266: the risk index editor -- its store (cfg.Template / cfg.ItemOverride riskindex rows, the findings sample) and its
// one staged change (the whole edited index), committed through the same Review & commit
builder.Services.AddSingleton<SI.Management.Web.RiskIndex.IRiskIndexStore, SI.Management.Web.RiskIndex.SqlRiskIndexStore>();
builder.Services.AddSingleton<SI.Management.Web.RiskIndex.RiskIndexChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SI.Management.Web.RiskIndex.RiskIndexChanges>());
// #274 / #275 G7: Reports -- the report catalog, templates, custom reports, output scopes and per-report weights
// (cfg.ItemOverride rareport / outputscope / weights), one staged-change handler; the Test button's read-only query runner
builder.Services.AddSingleton<SI.Management.Web.Reports.IReportStore, SI.Management.Web.Reports.SqlReportStore>();
builder.Services.AddSingleton<SI.Management.Web.Reports.ReportChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SI.Management.Web.Reports.ReportChanges>());
if (string.IsNullOrWhiteSpace(estate.WorkspaceId)) builder.Services.AddSingleton<SI.Management.Web.Reports.IReportQueryRunner, SI.Management.Web.Reports.NotConfiguredReportQueryRunner>();
else builder.Services.AddSingleton<SI.Management.Web.Reports.IReportQueryRunner, SI.Management.Web.Reports.LogAnalyticsReportQueryRunner>();
// #275 L4: the profiling and tagging editors -- ONE item storage seam (cfg.Template / cfg.ItemOverride / cfg.Document), a
// store per family and its staged change, committed through the same Review & commit
builder.Services.AddSingleton<IItemSource, SqlItemSource>();
builder.Services.AddSingleton<RuleItemStore>();
builder.Services.AddSingleton<RuleItemChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<RuleItemChanges>());
builder.Services.AddSingleton<TaggingStore>();
builder.Services.AddSingleton<TaggingChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<TaggingChanges>());
builder.Services.AddSingleton<SchemaOverlayStore>();
builder.Services.AddSingleton<SchemaOverlayChanges>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SchemaOverlayChanges>());
// continuous discovery ("New context available"): what each source offers, read from the two tables the engine fills; the
// columns an Admin promoted join the default layout of the views (kept with the column layouts)
builder.Services.AddSingleton<SI.Management.Web.NewContext.INewContextStore, SI.Management.Web.NewContext.SqlNewContextStore>();
builder.Services.AddSingleton<SI.Management.Web.Columns.IColumnPromotions, SI.Management.Web.Columns.ColumnPromotions>();
// V3-DATA-MODEL 2.12: the output maps (which columns each output sends, under which names) -- 'datamodel' template rows,
// the customer's column changes as cfg.ItemOverride rows, staged and committed through Review & commit
builder.Services.AddSingleton<SI.Management.Web.Outputs.OutputMapStore>();
builder.Services.AddSingleton<SI.Management.Web.Outputs.OutputMapChanges>();
// owner 2026-10-19: the 10-row preview of the column builder (Fields sent / Workbook fields)
builder.Services.AddSingleton<SI.Management.Web.Outputs.OutputRowPreview>();
// owner 2026-10-19: the test mode export of a vulnerability connector (Connectors > Scope)
builder.Services.AddSingleton<SI.Management.Web.Outputs.ScopeExport>();
// owner 2026-10-20: the ServiceNow team pack of a ServiceNow output (Connectors > Fields sent)
builder.Services.AddSingleton<SI.Management.Web.Outputs.ServiceNowTeamPack>();
// owner 2026-10-20: the ServiceNow setup and its checks (Connectors > Setup) -- the newest check per output (cfg.ServiceNowCheck,
// written by the engine identity), "Verify" (starts the mail job: the web app never signs in to ServiceNow) and the row counts
builder.Services.AddSingleton<SI.Management.Web.Outputs.IServiceNowCheckStore, SI.Management.Web.Outputs.SqlServiceNowCheckStore>();
builder.Services.AddSingleton<SI.Management.Web.Outputs.ServiceNowVerifier>();
builder.Services.AddSingleton<SI.Management.Web.Outputs.ServiceNowRowCount>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SI.Management.Web.Outputs.OutputMapChanges>());
// #404 (CONFIG-1): the change journal, undo, configuration backups, selective restore and the second person
builder.Services.AddSingleton(_ => SI.Management.Web.ChangeJournal.ConfigEntities.Default);
builder.Services.AddSingleton<SI.Management.Web.ChangeJournal.ConfigSettings>();
builder.Services.AddSingleton<SI.Management.Web.ChangeJournal.ConfigApplier>();
builder.Services.AddSingleton<SI.Management.Web.ChangeJournal.IConfigJournalStore, SI.Management.Web.ChangeJournal.SqlConfigJournalStore>();
builder.Services.AddSingleton<SI.Management.Web.ChangeJournal.IConfigBackupStore, SI.Management.Web.ChangeJournal.SqlConfigBackupStore>();
builder.Services.AddSingleton<SI.Management.Web.ChangeJournal.IConfigApprovalStore, SI.Management.Web.ChangeJournal.SqlConfigApprovalStore>();
builder.Services.AddSingleton<SI.Management.Web.ChangeJournal.ICollectionSendStore, SI.Management.Web.ChangeJournal.SqlCollectionSendStore>();
builder.Services.AddSingleton<SI.Management.Web.ChangeJournal.ConfigRevertHandler>();
builder.Services.AddSingleton<IStagedChangeHandler>(sp => sp.GetRequiredService<SI.Management.Web.ChangeJournal.ConfigRevertHandler>());
// #903: a committed "Switch on" of the ServiceNow data-out connector switches its outputs on (SI_DataOut_Outputs)
builder.Services.AddSingleton<SI.Management.Web.Outputs.DataOutSwitch>();
builder.Services.AddSingleton<ChangeService>();
builder.Services.Configure<SI.Management.Web.Timing.PageTimingOptions>(builder.Configuration.GetSection(SI.Management.Web.Timing.PageTimingOptions.Section));
builder.Services.Configure<JobsOptions>(builder.Configuration.GetSection(JobsOptions.Section));
var jobs = builder.Configuration.GetSection(JobsOptions.Section).Get<JobsOptions>() ?? new JobsOptions();
// #302: every job the web app starts for a person carries who started it (SI_AUDIT_CID + the attribution row)
if (jobs.IsConfigured)
{
    builder.Services.AddHttpClient<ArmJobsClient>();
    // CR8 (framework 12.11f item 1): with start-only rights on the jobs (Jobs:ChangeMode = request) a trigger change is a
    // request the pipeline runner applies; the default changes it directly, as before
    // #931: a start with values never carries a template (Azure Container Apps: that needs jobs/write) -- the values go to
    // the database as a start request the job claims (StartRequestJobsClient), in both modes
    if (jobs.ChangesAreRequests)
        builder.Services.AddTransient<IJobsClient>(sp => new RequestedTriggerJobsClient(
            new SI.Management.Web.Audit.AttributedJobsClient(new StartRequestJobsClient(sp.GetRequiredService<ArmJobsClient>(), sp.GetRequiredService<ISqlExecutor>()), sp.GetRequiredService<SI.Management.Web.Audit.IChangeAttributionWriter>()),
            sp.GetRequiredService<ISqlExecutor>()));
    else
        builder.Services.AddTransient<IJobsClient>(sp => new SI.Management.Web.Audit.AttributedJobsClient(new StartRequestJobsClient(sp.GetRequiredService<ArmJobsClient>(), sp.GetRequiredService<ISqlExecutor>()), sp.GetRequiredService<SI.Management.Web.Audit.IChangeAttributionWriter>()));
}
else builder.Services.AddSingleton<IJobsClient, NotConfiguredJobsClient>();
// #269: the daily job flow's definition + run records (cfg.JobFlow / cfg.FlowRun / cfg.FlowStepRun)
builder.Services.AddSingleton<IFlowStore, SqlFlowStore>();
// #636: is the Risk Analysis Summary step on? (the executive view, the wall board, the management summary, Risks > Summary)
builder.Services.AddSingleton<SI.Management.Web.Jobs.ISummaryStep, SI.Management.Web.Jobs.SummaryStep>();
if (string.IsNullOrWhiteSpace(estate.WorkspaceId)) builder.Services.AddSingleton<IConsoleLogReader, NotConfiguredConsoleLogReader>();
else builder.Services.AddSingleton<IConsoleLogReader, LogAnalyticsConsoleLogReader>();
builder.Services.AddSingleton<WebSettings>();
// the installation default for the number format (SIWeb_NumberFormatDefault), read by the display-culture provider
builder.Services.AddSingleton<SI.Management.Web.Pages.NumberFormatDefault>();
// #285: the header context bar (environment, mode, update ring, tenant, data source)
builder.Services.AddSingleton<SI.Management.Web.Pages.HeaderContext>();
// the chat: whether the tool calls show under every answer (SIWeb_Chat_ShowToolCalls; off = on demand)
builder.Services.AddSingleton<SI.Management.Web.ChatView.ChatDisplay>();
builder.Services.AddHttpClient<IKeyVaultSecretReader, KeyVaultSecretReader>();
// the web app never writes a secret: a pasted secret is encrypted with the updater's public hand-over key and left in
// cfg.PendingSecret; the updater stores it in Key Vault and points the setting at its name (no Key Vault right here)
builder.Services.AddSingleton<SI.Management.Web.Settings.ISecretHandoverStore, SI.Management.Web.Settings.SqlSecretHandoverStore>();
builder.Services.AddTransient<SI.Management.Web.Settings.SecretHandoverService>();
builder.Services.AddTransient<SI.Management.Web.Settings.AiKeyStore>();
builder.Services.AddSingleton<INonceStore, ChangeLogNonceStore>();
builder.Services.AddSingleton<MagicLinkService>();
builder.Services.AddSingleton<DeepLinks>();
// #258: external advisors per department, department sign-in links (per person, single use, revocable, the one-time code
// before an approval), and the department people as off-ladder roles in the role framework; comments on a finding.
builder.Services.AddSingleton<SI.Management.Web.Advisors.IAdvisorStore, SI.Management.Web.Advisors.SqlAdvisorStore>();
builder.Services.AddSingleton<SI.Management.Web.Advisors.IDepartmentSignInStore, SI.Management.Web.Advisors.SqlDepartmentSignInStore>();
builder.Services.AddSingleton<SI.Management.Web.Advisors.ISignInMailer, SI.Management.Web.Advisors.OutboxSignInMailer>();
// The ONE mail transport (SI_Mail_Mode none | smtp | sharedMailbox): its recorded status (cfg.InstallState
// 'MailRestriction' + attestation, the newest 'mail-test' outbox row), the shared verdict for Settings > E-mail + links
// and the home banner, the banner's Verify (starts the mail job's restriction re-check), and the guided setup (Exchange
// Online through module-free REST with the admin's delegated token). Test mails go through the outbox above.
builder.Services.AddSingleton<SI.Management.Web.Settings.IMailStatusStore, SI.Management.Web.Settings.SqlMailStatusStore>();
builder.Services.AddSingleton<SI.Management.Web.Settings.MailOverviewLoader>();
builder.Services.AddSingleton<SI.Management.Web.Settings.MailVerifier>();
builder.Services.AddHttpClient<SI.Management.Web.Settings.IExchangeAdminClient, SI.Management.Web.Settings.ExchangeAdminClient>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<SI.Management.Web.Settings.IExchangeTokenSource, SI.Management.Web.Settings.DelegatedExchangeTokenSource>();
builder.Services.AddTransient<SI.Management.Web.Settings.MailSetupFlow>();
builder.Services.AddSingleton<SI.Management.Web.Advisors.DepartmentSignInService>();
builder.Services.AddSingleton<IDepartmentGrants, SI.Management.Web.Advisors.DepartmentGrants>();
builder.Services.AddSingleton<SI.Management.Web.FindingComments.IFindingCommentStore, SI.Management.Web.FindingComments.SqlFindingCommentStore>();
builder.Services.AddSingleton<SI.Management.Web.FindingComments.FindingCommentService>();
// #265: follow-up tasks on a finding (cfg.FindingTask + history) and the ONE thread of a finding (governance log + comments
// + task history, read side by side)
builder.Services.AddSingleton<SI.Management.Web.Tasks.IFindingTaskStore, SI.Management.Web.Tasks.SqlFindingTaskStore>();
builder.Services.AddSingleton<SI.Management.Web.Tasks.FindingTaskService>();
builder.Services.AddSingleton<SI.Management.Web.Tasks.FindingThreadService>();
// #272: the ONE registry of actions on selected findings (a new action = its class + one line in AddFindingActions)
SI.Management.Web.Actions.FindingActionRegistration.AddFindingActions(builder.Services);
// Get Started (Admin): the setup steps, each checked from the install's data on every visit; the menu's red ! reads the
// same evaluation, cached in memory for a minute. Nothing is stored.
builder.Services.AddSingleton<SI.Management.Web.GetStarted.IGetStartedFactsSource, SI.Management.Web.GetStarted.GetStartedFactsReader>();
builder.Services.AddSingleton<SI.Management.Web.GetStarted.GetStartedService>();
// MAIL-2 notifications + the daily Get Started reminder, ENV-REPORT-1, CONFIG-IO-1 (Notify/WebFeatureServices.cs)
SI.Management.Web.Notify.WebFeatureServices.AddWebFeatures(builder.Services, builder.Configuration);
var app = builder.Build();

app.UseForwardedHeaders();
// CR7 Option A: behind the front a redeemed link browses under /MagicLink/s/ with its own session (Auth/LinkArea.cs)
if (signinFront) LinkArea.UseLinkArea(app);
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // behind the sign-in front the front sets the security headers (HSTS, CSP, frame-ancestors): one variant for SI and PIM
    if (!signinFront) app.UseHsts();
}
app.Use(async (ctx, next) =>
{
    if (!signinFront)
    {
        var h = ctx.Response.Headers;
        h["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://login.microsoftonline.com";
        h["X-Content-Type-Options"] = "nosniff";
        h["Referrer-Policy"] = "no-referrer";
        h["X-Frame-Options"] = "DENY";
    }
    // the request's source notes, for code without services at hand (the Excel export adds them to its info sheet)
    SI.Management.Web.Collection.SourceNoteScope.Current = ctx.RequestServices.GetService<SI.Management.Web.Collection.ISourceNotes>();
    await next();
});
// "What does this script do?" next to every SecurityInsight script a page names (framework section 12.7 SCRIPT-DOC-1)
SI.Management.Web.Links.ScriptDocLinkExtensions.UseScriptDocLinks(app);

// Numbers on screen in the viewer's regional format (their own choice, the installation default, else Accept-Language;
// en-US fallback) -- display only, see DisplayCulture.
app.UseRequestLocalization(SI.Management.Web.Pages.DisplayCulture.Options());
app.UseRouting();
// CR7 Option A: inside the link area only the endpoints a link session may reach at all (Auth/LinkArea.cs)
if (signinFront) LinkArea.UseLinkAreaEndpointGate(app);
// The page timing log: a request slower than PageTiming:SlowMs writes one line (route, status, time, database calls and
// the slowest statement's shape) -- after routing, so the route is known; static files and the health probe are not timed.
app.UsePageTiming();
app.UseAuthentication();
app.UseAuthorization();
// #636: an old address of a retired page, opened in a browser, opens the page / named view that replaced it
app.Use((ctx, next) => SI.Management.Web.Navigation.RetiredPages.Middleware(ctx, () => next()));
app.UseStaticFiles();   // after authorization on purpose: the fallback policy covers the assets too

// The only anonymous endpoint. It says the process is up -- nothing about version, configuration or data.
app.MapGet("/healthz", () => Results.Text("ok", "text/plain")).AllowAnonymous();
// Which build this is, for support: signed-in only (the fallback policy), read from BUILD.json -- no state, no data.
// Every open page also asks it every 5 minutes (#345, version-check.js) to offer "a new version is available" --
// so never cached: a cached answer would hide the very deploy it is there to notice.
app.MapGet("/about", (HttpContext ctx) =>
{
    ctx.Response.Headers.CacheControl = "no-store";
    var b = SI.Management.Web.Pages.AppInfo.Build;
    return Results.Json(new
    {
        product = SI.Management.Web.Pages.AppInfo.Product,
        version = b.Version,
        display = b.Display,
        commit = b.Commit,
        shortCommit = b.ShortCommit,
        builtUtc = b.BuiltUtc,
        rc = b.Rc,
        channel = b.Channel,
        ring = b.Ring,
        build = b.Line,
    });
});
// behind the sign-in front, /signout is the front's (it never reaches this app)
if (!signinFront)
app.MapGet("/signout", async ctx =>
{
    // a sign-out ends access: on the audit trail (#260) -- the write never blocks the sign-out
    var audit = new SI.Management.Web.Audit.AuditScope("signin.session.end", SI.Management.Web.Audit.AuditScope.ActorOf(ctx.User), SI.Management.Web.Audit.AuditScope.SourceOf(ctx.User)) { Target = "/signout" };
    await ctx.RequestServices.GetRequiredService<SI.Management.Web.Audit.IAuditWriter>().WriteAsync(audit.ToRecord(SI.Management.Web.Audit.AuditOutcomes.Ok, null), CancellationToken.None);
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
});
app.MapRazorPages();

app.Run();

public partial class Program { }
