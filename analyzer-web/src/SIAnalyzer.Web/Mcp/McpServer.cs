using System.Text.Json;
using System.Text.Json.Nodes;
using SIAnalyzer.Core.Ai;
using SIAnalyzer.Core.Kql;
using SIAnalyzer.Web.Services;

namespace SIAnalyzer.Web.Mcp;

/// <summary>
/// A minimal Model Context Protocol (MCP) server over JSON-RPC 2.0. It exposes the SAME guarded
/// surface as the web UI - prestaged analyses, a guarded ad-hoc query, and the
/// snapshot/diff/timeline - so an MCP client (e.g. an agent) can pull SI Analyzer facts under the
/// IDENTICAL read-only guardrail + grounding contract. It is authenticated by the host (Easy Auth)
/// like every other endpoint, and every "query" tool routes through <see cref="KqlGuardrail"/>.
///
/// AUDIT #11 (2026-08-05) - this file used to claim "it never exposes a write tool" and
/// "(no write tools exist)" while shipping <c>send_exec_summary_email</c>, which transmits mail to
/// the configured executive recipients. That is an outbound side effect, and an agent acting on
/// this surface could trigger it.
///
/// The contract now reads: <b>READ-ONLY except for exactly ONE declared side-effecting tool</b>,
/// and three things follow from saying so out loud:
///   * the tool is marked <see cref="ToolDef.HasSideEffects"/>, surfaced in <c>tools/list</c> as
///     <c>annotations.readOnlyHint=false</c> AND with a "SIDE EFFECT:" prefix in its description,
///     so a client can tell before it calls;
///   * it ships OFF (<c>SIAnalyzer:Mcp:AllowEmailSend</c>, default false). An agent that connects
///     gets a genuinely read-only catalogue - it is not even listed - unless an operator widens it
///     deliberately. Same instinct as the governance platform-sync: a surface with an external
///     effect is not on by accident;
///   * a call to it while disabled is refused by the server, not just hidden from the listing.
/// </summary>
public static class McpServer
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <param name="HasSideEffects">True when the tool does something OUTSIDE this app (today:
    /// sends email). Everything else only reads.</param>
    public sealed record ToolDef(string Name, string Description, JsonObject InputSchema, bool HasSideEffects = false);

    /// <summary>
    /// The tool catalogue. Every entry is read-only EXCEPT the one flagged
    /// <see cref="ToolDef.HasSideEffects"/> - see <see cref="ToolsFor"/>, which is what the server
    /// actually lists, and which drops the side-effecting tool unless it has been enabled.
    /// </summary>
    public static IReadOnlyList<ToolDef> Tools { get; } = new[]
    {
        new ToolDef("list_prestaged_analyses",
            "List the one-click, plain-language prestaged security analyses (read-only).",
            EmptySchema()),
        new ToolDef("run_prestaged_analysis",
            "Run a prestaged analysis by id and return its findings + a grounded plain-language explanation (read-only).",
            ObjSchema(("id", "string", "The prestaged analysis id."))),
        new ToolDef("guarded_query",
            "Run a read-only KQL query over the allow-listed SI tables. The query is rejected unless it passes the read-only guardrail (no writes, no control commands, allow-listed tables only).",
            ObjSchema(("kql", "string", "A read-only KQL query."))),
        new ToolDef("snapshot_diff",
            "Return what changed since the previous snapshot: new / closed / open / regressed / improved findings + score delta (read-only).",
            EmptySchema()),
        new ToolDef("score_timeline",
            "Return the risk-score timeline across snapshots (total + per-tier per CollectionTime) (read-only).",
            EmptySchema()),
        new ToolDef("exec_headline",
            "Return the one-sentence 'if you read one thing' executive headline verdict: the posture band, its direction, and how many concrete remediation actions would move the score to the next-better band - all grounded in the latest snapshot, no invented numbers (read-only).",
            EmptySchema()),
        new ToolDef("exec_summary",
            "Return the board-ready executive posture summary + headline risk score and direction (read-only).",
            EmptySchema()),
        new ToolDef("period_comparison",
            "Compare the latest posture against a baseline snapshot chosen by a reporting period (e.g. 'quarter' = since last board meeting): new/resolved/worse/improved counts + score delta vs that baseline (read-only).",
            ObjSchema(("period", "string", "Reporting period key: previous | month | quarter | half | year. Defaults to quarter."))),
        new ToolDef("risk_by_area",
            "Return where risk concentrates by area (identity / endpoint / cloud / internet-facing): each area's score, share of total, finding count, period direction and biggest contributor (read-only).",
            EmptySchema()),
        new ToolDef("top_movers",
            "Return the trends & top movers: which areas improved the most and which got worse the most since the baseline snapshot, plus a by-area / by-severity / by-tier breakdown of the score change. Honest when only one snapshot exists (no comparison). All deltas are grounded score sums, nothing projected (read-only).",
            OptionalObjSchema(("period", "string", "Reporting period key for the baseline: previous | month | quarter | half | year. Defaults to quarter."))),
        new ToolDef("business_impact",
            "Return the 'so what' business-impact framing of the top risks: each top finding translated into a plain-language business consequence (data exposure / downtime / compliance / reputation) plus the grounded technical driver it came from (read-only).",
            EmptySchema()),
        new ToolDef("drilldown",
            "Return the grounded evidence behind a headline number: the contributing findings that sum to the overall score, a domain, a severity band or a tier - with each finding's share. Proves no number is a black box (read-only).",
            OptionalObjSchema(
                ("dimension", "string", "What to drill into: overall | domain | severity | tier. Defaults to overall."),
                ("key", "string", "The slice within the dimension (e.g. domain 'identity', severity 'Critical'). Omit for overall."))),
        new ToolDef("remediation_plan",
            "Return the prioritised remediation plan: the next actions ranked by risk-removed-per-effort (ROI). Each action groups all of one asset's findings into a single fix with its projected score drop, an effort estimate (Low/Medium/High), a plain recommendation, and the running cumulative score + band after doing it; plus how many actions move the posture to the next-better band. All grounded in the latest snapshot - effort/ROI are clearly-labelled estimates, no costs or dates (read-only).",
            OptionalObjSchema(("top", "integer", "How many actions to return (default 5). The ranking + band maths consider every asset regardless."))),
        new ToolDef("glossary",
            "Return the plain-language exec glossary ('what these terms mean'): each security term used on the executive surface (risk score, severity, criticality tier, crown jewel, exposure, vulnerability/CVE, stale privileged account, onboarding gap, remediation, snapshot) defined for a non-technical reader, with a GROUNDED example pulled from the real latest-snapshot rows where the concept is present - and an honest 'not seen in your current data' note where it is absent. Present-now terms are flagged. No invented numbers (read-only).",
            EmptySchema()),
        new ToolDef("org_coaching",
            "Return the organisational / process maturity gaps the finding PATTERNS imply ('missing processes') - beyond per-asset tickets. Each gap is a leadership theme (e.g. privileged-access reviews, internet-exposure reviews, patch & lifecycle cadence, asset onboarding, ownership, crown-jewel protection) with a plain finding, a coaching-style recommendation framed as a process/behaviour, the number of affected assets, and grounded example asset names. Only surfaced when real rows cross an evidence threshold; honest empty result when no systemic gap stands out. No invented numbers (read-only).",
            EmptySchema()),
        new ToolDef("maturity_scorecard",
            "Return the security maturity scorecard + roadmap ('where the environment and behaviour need to mature so these findings stop coming back'): a rule-based 0-100 maturity score and plain band (Initial/Developing/Defined/Managed) per leadership dimension (Tiering, Privileged Access, Identity Hygiene, Exposure Management, Visibility & Coverage, Operating Discipline), each grounded in the latest-snapshot rows (the score is the share of in-scope assets WITHOUT a weakness signal - a real partition, never invented), with the weak-asset count, the in-scope denominator, grounded example asset names, and the leadership 'mature here next' move. Dimensions with no in-scope asset are honestly reported as 'not enough data', never given a fabricated score. The roadmap lists only the below-bar dimensions with real evidence, most-impactful first; empty when no systemic gap stands out. No invented numbers (read-only).",
            EmptySchema()),
        new ToolDef("send_exec_summary_email",
            "SIDE EFFECT: SENDS EMAIL. This is the only tool here that acts outside the app - it transmits the grounded exec-summary digest to the configured executive recipients (the same one the scheduled send delivers: headline verdict, score/band, top risks, recommended actions + a board-deck link). Everything else on this server only reads. Fail-soft: returns a 'not configured' result when no recipients/SMTP are set, and it never sends invented data.",
            EmptySchema(),
            HasSideEffects: true),
    };

    /// <summary>
    /// The tools this server will actually list and serve. The side-effecting tool is present only
    /// when <paramref name="allowEmailSend"/> is on, so the default surface an agent sees is
    /// genuinely read-only rather than read-only-with-a-footnote.
    /// </summary>
    public static IReadOnlyList<ToolDef> ToolsFor(bool allowEmailSend) =>
        allowEmailSend ? Tools : Tools.Where(t => !t.HasSideEffects).ToList();

    /// <summary>
    /// Handle one JSON-RPC message. Returns the response node, or NULL when the message is a
    /// notification and the protocol requires silence.
    ///
    /// The optional <paramref name="email"/> service and <paramref name="allowEmailSend"/> together
    /// enable the one side-effecting tool; without both, it is neither listed nor callable.
    /// </summary>
    public static async Task<JsonNode?> HandleAsync(
        JsonNode request, AnalyzerService svc, CancellationToken ct,
        ExecEmailService? email = null, bool allowEmailSend = false, ILogger? log = null)
    {
        var method = request["method"]?.GetValue<string>() ?? "";

        // AUDIT #11: a JSON-RPC NOTIFICATION - a message with no "id" - must receive NO reply at
        // all. Every spec-compliant MCP client sends notifications/initialized straight after
        // initialize; this server used to answer it with a "Method not found" error, which is both
        // a protocol violation and the first thing such a client sees.
        var hasId = request is JsonObject obj && obj.ContainsKey("id") && request["id"] is not null;
        if (!hasId) return null;

        var id = request["id"]!.DeepClone();

        try
        {
            JsonNode? result = method switch
            {
                "initialize" => Initialize(),
                "tools/list" => ListTools(allowEmailSend),
                "tools/call" => await CallToolAsync(request["params"], svc, email, allowEmailSend, ct),
                _ => throw new McpError(-32601, $"Method not found: {method}"),
            };
            return new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result };
        }
        catch (McpError e)
        {
            // McpError messages are written FOR the caller (bad arguments, a rejected query) - they
            // are safe to return verbatim.
            return ErrorResponse(id, e.Code, e.Message);
        }
        catch (Exception e)
        {
            // AUDIT #11: an unexpected exception's message is internal - connection strings, paths,
            // SDK internals - and used to be handed straight to the caller. Log it in full, return
            // a generic failure.
            log?.LogError(e, "MCP tool call failed ({Method}).", method);
            return ErrorResponse(id, -32603, "Internal error handling the request. See the server log for details.");
        }
    }

    private static JsonNode Initialize() => new JsonObject
    {
        ["protocolVersion"] = "2024-11-05",
        ["serverInfo"] = new JsonObject { ["name"] = "securityinsight-analyzer", ["version"] = "0.1.0" },
        ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
    };

    private static JsonNode ListTools(bool allowEmailSend)
    {
        var arr = new JsonArray();
        foreach (var t in ToolsFor(allowEmailSend))
        {
            arr.Add(new JsonObject
            {
                ["name"] = t.Name,
                ["description"] = t.Description,
                ["inputSchema"] = t.InputSchema.DeepClone(),
                // MCP tool annotations: readOnlyHint tells a client whether calling this changes
                // anything outside the app. Stated for EVERY tool, not just the one that does -
                // "unannotated" and "read-only" must not be the same thing to a caller.
                ["annotations"] = new JsonObject { ["readOnlyHint"] = !t.HasSideEffects },
            });
        }
        return new JsonObject { ["tools"] = arr };
    }

    private static async Task<JsonNode> CallToolAsync(JsonNode? prms, AnalyzerService svc, ExecEmailService? email, bool allowEmailSend, CancellationToken ct)
    {
        var name = prms?["name"]?.GetValue<string>() ?? throw new McpError(-32602, "Missing tool name.");
        var args = prms?["arguments"] as JsonObject ?? new JsonObject();

        // Refused, not merely unlisted: a client that already knows the name must not be able to
        // call a disabled side-effecting tool.
        var def = Tools.FirstOrDefault(t => t.Name == name);
        if (def is { HasSideEffects: true } && !allowEmailSend)
        {
            throw new McpError(-32601, $"Tool '{name}' has an external side effect (it sends email) and is disabled on this server. Enable SIAnalyzer:Mcp:AllowEmailSend to expose it.");
        }

        string text;
        switch (name)
        {
            case "list_prestaged_analyses":
                text = JsonSerializer.Serialize(svc.GetPrestaged().Select(a => new { a.Id, a.Title, a.Plain, a.Domain }), Json);
                break;
            case "run_prestaged_analysis":
            {
                var id = args["id"]?.GetValue<string>() ?? throw new McpError(-32602, "Missing 'id'.");
                var r = await svc.RunPrestagedAsync(id, Audience.Analyst, ct);
                text = JsonSerializer.Serialize(new { r.Title, columns = r.Result.Columns, rowCount = r.Result.Rows.Count, narrative = r.Narrative, narrativeFromAi = r.NarrativeFromAi }, Json);
                break;
            }
            case "guarded_query":
            {
                var kql = args["kql"]?.GetValue<string>() ?? throw new McpError(-32602, "Missing 'kql'.");
                var g = KqlGuardrail.Check(kql);
                if (!g.Allowed) throw new McpError(-32000, "Query rejected by read-only guardrail: " + string.Join("; ", g.Reasons));
                var r = await svc.RunRawKqlAsync(kql, Audience.Analyst, ct);
                text = JsonSerializer.Serialize(new { columns = r.Result?.Columns, rowCount = r.Result?.Rows.Count ?? 0, narrative = r.Narrative }, Json);
                break;
            }
            case "snapshot_diff":
            {
                var m = await svc.GetManagementAsync(ct);
                text = JsonSerializer.Serialize(new { m.Diff.NewCount, m.Diff.ClosedCount, m.Diff.OpenCount, m.Diff.RegressedCount, m.Diff.ImprovedCount, m.Diff.ScoreDelta, m.Diff.CurrentTotal, m.Diff.PreviousTotal }, Json);
                break;
            }
            case "score_timeline":
            {
                var m = await svc.GetManagementAsync(ct);
                text = JsonSerializer.Serialize(m.Timeline.Select(p => new { date = p.CollectionTime, p.TotalScore, p.FindingCount, p.PercentFromPrev }), Json);
                break;
            }
            case "exec_headline":
            {
                var e = await svc.GetExecAsync(null, ct);
                var hl = e.Dashboard.Headline;
                text = JsonSerializer.Serialize(new
                {
                    hl.Sentence,
                    hl.Band,
                    hl.Direction,
                    hl.Score,
                    hl.ScoreDelta,
                    hl.PercentChange,
                    hl.NextBand,
                    hl.ActionsToNextBand,
                }, Json);
                break;
            }
            case "exec_summary":
            {
                var e = await svc.GetExecAsync(null, ct);
                text = JsonSerializer.Serialize(new { e.Dashboard.HeadlineScore, e.Dashboard.ScoreBand, e.Dashboard.Direction, e.Dashboard.ScoreDelta, summary = e.ExecSummary, summaryFromAi = e.SummaryFromAi }, Json);
                break;
            }
            case "period_comparison":
            {
                var key = args["period"]?.GetValue<string>();
                var e = await svc.GetExecAsync(key, ct);
                var p = e.Dashboard.Period;
                text = JsonSerializer.Serialize(new
                {
                    period = p.Period.Label,
                    p.HasBaseline,
                    baseline = p.BaselineTime,
                    current = p.CurrentTime,
                    p.DaysSpanned,
                    p.BaselineExact,
                    scoreDelta = p.Diff.ScoreDelta,
                    p.Diff.NewCount,
                    p.Diff.ClosedCount,
                    p.Diff.RegressedCount,
                    p.Diff.ImprovedCount,
                }, Json);
                break;
            }
            case "risk_by_area":
            {
                var e = await svc.GetExecAsync(null, ct);
                var c = e.Dashboard.Concentration;
                text = JsonSerializer.Serialize(new
                {
                    c.TotalScore,
                    mostConcentrated = c.MostConcentratedArea,
                    areas = c.Areas.Select(a => new { area = a.Plain, a.Score, a.SharePercent, a.Findings, a.Direction, a.ChangePercent, a.TopContributor }),
                }, Json);
                break;
            }
            case "top_movers":
            {
                var key = args["period"]?.GetValue<string>();
                var e = await svc.GetExecAsync(key, ct);
                var mv = e.Dashboard.Movers;
                text = JsonSerializer.Serialize(new
                {
                    mv.HasComparison,
                    baseline = mv.BaselineTime,
                    current = mv.CurrentTime,
                    mv.TotalDelta,
                    biggestImprovements = mv.BiggestImprovements.Select(x => new { area = x.Plain, x.PreviousScore, x.CurrentScore, x.Delta, x.ChangePercent, x.Direction }),
                    biggestIncreases = mv.BiggestRegressions.Select(x => new { area = x.Plain, x.PreviousScore, x.CurrentScore, x.Delta, x.ChangePercent, x.Direction }),
                    breakdown = mv.Groups.Select(g => new
                    {
                        dimension = g.Plain,
                        moves = g.Moves.Where(x => x.Direction != "steady").Select(x => new { slice = x.Plain, x.Delta, x.ChangePercent, x.Direction }),
                    }),
                }, Json);
                break;
            }
            case "business_impact":
            {
                var e = await svc.GetExecAsync(null, ct);
                var b = e.Dashboard.BusinessImpact;
                text = JsonSerializer.Serialize(new
                {
                    byCategory = b.ByCategory.Select(s => new { category = s.Label, findings = s.Value }),
                    items = b.Items.Select(i => new { i.ConfigurationName, i.SecuritySeverity, i.CriticalityTier, i.RiskScoreTotal, i.Category, i.Consequence, i.Why }),
                }, Json);
                break;
            }
            case "drilldown":
            {
                var dimension = args["dimension"]?.GetValue<string>() ?? "overall";
                var key = args["key"]?.GetValue<string>();
                var dd = await svc.GetDrilldownAsync(dimension, key, 10, ct);
                text = JsonSerializer.Serialize(new
                {
                    dd.Dimension,
                    dd.Key,
                    dd.Plain,
                    dd.Total,
                    dd.ContributorCount,
                    dd.ShownScore,
                    items = dd.Items.Select(i => new { i.ConfigurationName, i.SecurityDomain, i.SecuritySeverity, i.RiskScoreTotal, i.SharePercent, i.Why }),
                }, Json);
                break;
            }
            case "remediation_plan":
            {
                var top = args["top"]?.GetValue<int>() ?? 5;
                var p = await svc.GetRemediationPlanAsync(top, ct);
                text = JsonSerializer.Serialize(new
                {
                    p.StartScore,
                    p.StartBand,
                    p.TotalAssets,
                    projectedScoreAfterPlan = p.ProjectedScoreAfterPlan,
                    projectedBandAfterPlan = p.ProjectedBandAfterPlan,
                    nextBetterBand = p.NextBetterBand,
                    bandCrossActionCount = p.BandCrossActionCount,
                    actions = p.Actions.Select(a => new
                    {
                        a.Rank,
                        a.ConfigurationName,
                        area = a.AreaPlain,
                        a.CriticalityTier,
                        a.TopSeverity,
                        a.FindingCount,
                        a.ProjectedScoreDrop,
                        a.SharePercent,
                        a.Effort,
                        a.RoiScore,
                        a.Why,
                        a.Recommendation,
                        a.CumulativeScoreAfter,
                        a.BandAfter,
                        a.CrossesBandHere,
                    }),
                }, Json);
                break;
            }
            case "glossary":
            {
                var gv = await svc.GetGlossaryAsync(ct);
                text = JsonSerializer.Serialize(new
                {
                    gv.PresentCount,
                    gv.TotalCount,
                    terms = gv.Terms.Select(t => new { t.Term, t.Plain, t.Present, inYourData = t.InYourData }),
                }, Json);
                break;
            }
            case "org_coaching":
            {
                var cv = await svc.GetOrgCoachingAsync(ct);
                text = JsonSerializer.Serialize(new
                {
                    cv.HasGaps,
                    cv.AssetsConsidered,
                    gaps = cv.Gaps.Select(g => new { g.Theme, g.Finding, g.Recommendation, g.AffectedAssets, examples = g.Examples }),
                }, Json);
                break;
            }
            case "maturity_scorecard":
            {
                var mv = await svc.GetMaturityAsync(ct);
                text = JsonSerializer.Serialize(new
                {
                    mv.OverallScore,
                    mv.OverallRating,
                    mv.AssetsConsidered,
                    mv.HasRoadmap,
                    dimensions = mv.Dimensions.Select(d => new
                    {
                        d.Dimension, d.Plain, d.Score, d.Rating, d.WeakAssets, d.Considered,
                        d.HasData, examples = d.Examples, d.NextMove,
                    }),
                    roadmap = mv.Roadmap.Select(d => new
                    {
                        d.Dimension, d.Score, d.Rating, d.WeakAssets, examples = d.Examples, d.NextMove,
                    }),
                }, Json);
                break;
            }
            case "send_exec_summary_email":
            {
                if (email is null)
                    throw new McpError(-32000, "The exec-summary email service is not available in this context.");
                var r = await email.SendNowAsync(ct);
                text = JsonSerializer.Serialize(new { r.Sent, r.RecipientCount, r.Detail }, Json);
                break;
            }
            default:
                throw new McpError(-32601, $"Unknown tool: {name}");
        }

        return new JsonObject
        {
            ["content"] = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = text } },
            ["isError"] = false,
        };
    }

    private static JsonObject ErrorResponse(JsonNode? id, int code, string message) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message },
    };

    private static JsonObject EmptySchema() => new()
    {
        ["type"] = "object",
        ["properties"] = new JsonObject(),
    };

    private static JsonObject ObjSchema(params (string Name, string Type, string Desc)[] props)
    {
        var p = new JsonObject();
        var required = new JsonArray();
        foreach (var (n, t, d) in props)
        {
            p[n] = new JsonObject { ["type"] = t, ["description"] = d };
            required.Add(n);
        }
        return new JsonObject { ["type"] = "object", ["properties"] = p, ["required"] = required };
    }

    /// <summary>Like <see cref="ObjSchema"/> but every property is OPTIONAL (no required list).</summary>
    private static JsonObject OptionalObjSchema(params (string Name, string Type, string Desc)[] props)
    {
        var p = new JsonObject();
        foreach (var (n, t, d) in props)
        {
            p[n] = new JsonObject { ["type"] = t, ["description"] = d };
        }
        return new JsonObject { ["type"] = "object", ["properties"] = p };
    }

    private sealed class McpError(int code, string message) : Exception(message)
    {
        public int Code { get; } = code;
    }
}
