using System.ComponentModel;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using SI.Management.Core;

namespace SI.Management.Mcp;

public static class McpRoles
{
    public const string Admin = "Admin";
    public const string Viewer = "Viewer";
    // #253: the web app's top role; SuperAdmin includes everything Admin can do. "Reader" is accepted like "Viewer".
    public const string SuperAdmin = "SuperAdmin";
    public const string Reader = "Reader";
    public const string ReaderPolicy = "EstateReader";
}

/// The MCP face of the curated toolbox. Every tool is read-only and returns JSON:
/// { data, query, source, asOf } -- the data AND the exact query that produced it.
/// Each method forwards to <see cref="EstateToolbox"/>, the same code the chat service calls, so names, bounds
/// and results cannot drift between the two.
[McpServerToolType]
public sealed class EstateMcpTools(EstateToolbox toolbox, IHttpContextAccessor http)
{
    private bool IsAdmin => http.HttpContext?.User?.IsInRole(McpRoles.Admin) == true || http.HttpContext?.User?.IsInRole(McpRoles.SuperAdmin) == true;

    [McpServerTool(Name = EstateToolbox.TopRisks, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("The highest-risk assets in the newest Risk Analysis snapshot. One machine counts once (names are resolved to one asset id). Ranked by tier (0 = most critical) then weighted risk score. Returns the data and the query it ran.")]
    public Task<string> TopRisks(
        [Description("How many assets, 1-100 (default 20).")] int top = EstateToolbox.DefaultTop,
        CancellationToken ct = default)
        => Run(EstateToolbox.TopRisks, new { top }, ct);

    [McpServerTool(Name = EstateToolbox.AssetLookup, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("One asset by name or id (host name, FQDN, SecurityInsight asset id, Azure resource id, device id): tier, type, the other ids it carries, and its top findings. Returns the data and the query it ran.")]
    public Task<string> AssetLookup(
        [Description("Asset name or id. Letters, digits, spaces and . _ : / @ ( ) + # - only; max 400.")] string nameOrId,
        CancellationToken ct = default)
        => Run(EstateToolbox.AssetLookup, new { nameOrId }, ct);

    [McpServerTool(Name = EstateToolbox.RiskTrend, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Per day: the average risk score per finding (never a sum of scores), the findings, the findings at Very High or High severity, and the tier-0 assets with findings. Returns the data and the query it ran.")]
    public Task<string> RiskTrend(
        [Description("Days back, 1-365 (default 90).")] int days = EstateToolbox.DefaultDays,
        CancellationToken ct = default)
        => Run(EstateToolbox.RiskTrend, new { days }, ct);

    [McpServerTool(Name = EstateToolbox.DomainTrend, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Per day and security domain: the average risk score per finding (never a sum of scores) and the findings. Returns the data and the query it ran.")]
    public Task<string> DomainTrend(
        [Description("Days back, 1-365 (default 90).")] int days = EstateToolbox.DefaultDays,
        CancellationToken ct = default)
        => Run(EstateToolbox.DomainTrend, new { days }, ct);

    [McpServerTool(Name = EstateToolbox.VulnerabilityStateTool, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Vulnerability close-loop per week: new, fixed (verified remediated), reopened and open at week end. Returns the data and the query it ran.")]
    public Task<string> VulnerabilityState(
        [Description("Weeks back, 1-104 (default 12).")] int weeks = EstateToolbox.DefaultWeeks,
        CancellationToken ct = default)
        => Run(EstateToolbox.VulnerabilityStateTool, new { weeks }, ct);

    [McpServerTool(Name = EstateToolbox.RunHealth, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Engine run heartbeats (start/end, duration, exit reason), newest first. Returns the data and the query it ran.")]
    public Task<string> RunHealth(
        [Description("Days back, 1-365 (default 7).")] int days = EstateToolbox.DefaultRunHealthDays,
        CancellationToken ct = default)
        => Run(EstateToolbox.RunHealth, new { days }, ct);

    [Authorize(Roles = McpRoles.Admin)]
    [McpServerTool(Name = EstateToolbox.SettingsRead, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Admin only. Current non-secret settings and their change history. Returns the data and the queries it ran.")]
    public Task<string> SettingsRead(
        [Description("One setting name (letters, digits, _); omit for all.")] string? name = null,
        [Description("History days back, 1-365 (default 90).")] int days = EstateToolbox.DefaultDays,
        [Description("Max history rows, 1-200 (default 50).")] int rows = EstateToolbox.DefaultHistoryRows,
        CancellationToken ct = default)
        => Run(EstateToolbox.SettingsRead, new { name, days, rows }, ct);

    [McpServerTool(Name = EstateToolbox.FindingsQuery, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Findings of one Risk Analysis collection from the Pro database (newest unless collectionId is given), filtered and paged, most important first (asset tier, then risk score). Returns the data and the query it ran.")]
    public Task<string> FindingsQuery(
        [Description("A collection id; omit for the newest.")] string? collectionId = null,
        [Description("Asset tier: 0, 1, 2, 3 or Unclassified.")] string? tier = null,
        [Description("Severity: Very High, High, Medium-High, Medium or Low (there is no Critical; it is read as Very High). Omit for 'top' findings.")] string? severity = null,
        [Description("Security domain: Endpoint, Identity, Azure or PublicIP.")] string? domain = null,
        [Description("Risk Analysis report name, as listed by filter_values.")] string? report = null,
        [Description("endpoint, identity, azure or publicip.")] string? assetKind = null,
        [Description("Text matched literally in asset name, title, CVE, configuration id, report (max 200).")] string? text = null,
        [Description("importance (default), risk, severity (Very High first), severity-asc (Low first), asset or report.")] string? sort = null,
        [Description("Rows to skip (paging).")] int skip = 0,
        [Description("Rows, 1-100 (default 25).")] int top = 25,
        CancellationToken ct = default)
        => Run(EstateToolbox.FindingsQuery, new { collectionId, tier, severity, domain, report, assetKind, text, sort, skip, top }, ct);

    [McpServerTool(Name = EstateToolbox.TrendAnalytics, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Trend analytics from the Pro database: findings, assets, the average and the highest risk score per finding, and the Very High + High findings per day split by one dimension (tier, severity, domain, report or none), filtered by the others. Returns the data and the query it ran.")]
    public Task<string> TrendAnalytics(
        [Description("Days back, 1-730 (default 90).")] int days = EstateToolbox.DefaultDays,
        [Description("none, tier (default), severity, domain or report.")] string? dimension = null,
        [Description("Filter: asset tier 0-3 or Unclassified.")] string? tier = null,
        [Description("Filter: severity -- Very High, High, Medium-High, Medium or Low.")] string? severity = null,
        [Description("Filter: security domain -- Endpoint, Identity, Azure or PublicIP.")] string? domain = null,
        [Description("Filter: report name, as listed by filter_values.")] string? report = null,
        CancellationToken ct = default)
        => Run(EstateToolbox.TrendAnalytics, new { days, dimension, tier, severity, domain, report }, ct);

    [McpServerTool(Name = EstateToolbox.FilterValues, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("The values each findings filter takes in one collection, read from the data: severity (most severe first), tier, domain, report, asset kind and the sorts. Call it before concluding that something does not exist. Returns the data and the query it ran.")]
    public Task<string> FilterValues(
        [Description("A collection id; omit for the newest.")] string? collectionId = null,
        CancellationToken ct = default)
        => Run(EstateToolbox.FilterValues, new { collectionId }, ct);

    [McpServerTool(Name = EstateToolbox.VulnLifecycle, ReadOnly = true, Idempotent = true, Destructive = false, OpenWorld = false)]
    [Description("Vulnerability lifecycle from the Pro database: new, closed (verified fixed) and reopened per day, week or month, and open at period end. Returns the data and the queries it ran.")]
    public Task<string> VulnLifecycle(
        [Description("Days back, 1-730 (default 90).")] int days = EstateToolbox.DefaultDays,
        [Description("day, week (default) or month.")] string? grain = null,
        CancellationToken ct = default)
        => Run(EstateToolbox.VulnLifecycle, new { days, grain }, ct);

    private async Task<string> Run(string tool, object args, CancellationToken ct)
    {
        try
        {
            var output = await toolbox.InvokeAsync(tool, JsonSerializer.Serialize(args, EstateToolbox.Json), IsAdmin, ct).ConfigureAwait(false);
            return output.ResultJson;
        }
        catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException)
        {
            // The caller's mistake (bounds, pattern, role): say which, never echo a stack.
            throw new McpException(ex.Message);
        }
    }
}
