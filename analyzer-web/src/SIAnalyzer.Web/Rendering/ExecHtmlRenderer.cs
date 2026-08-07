using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using SIAnalyzer.Core.Exec;
using SIAnalyzer.Web.Services;

namespace SIAnalyzer.Web.Rendering;

/// <summary>
/// Renders the executive dashboard to a self-contained HTML document. Used by BOTH the
/// live Razor page (the server-rendered body) AND the static preview generator, so the
/// preview the operator opens locally is byte-for-byte the same visual as the hosted
/// exec surface. Mobile-friendly + accessible + print/PDF-friendly; charts are drawn
/// with a bundled Chart.js (offline copy under wwwroot/lib). NO KQL/jargon appears here.
/// </summary>
public static class ExecHtmlRenderer
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>
    /// Render a fully self-contained standalone HTML page (for the committed static
    /// preview): the bundled Chart.js is INLINED so the file opens locally with no server.
    /// </summary>
    public static string RenderStandalone(ExecViewModel vm, string chartJsSource) =>
        RenderBody(vm, chartJsHref: null, standalone: true, inlineChartJs: chartJsSource);

    /// <summary>Render the complete document. <paramref name="chartJsHref"/> points at
    /// the bundled Chart.js (e.g. "/lib/chart.umd.js" when hosted); pass
    /// <paramref name="inlineChartJs"/> instead to embed the library inline.
    /// <paramref name="nonce"/> is the per-request CSP nonce (audit #13) - required for a SERVED
    /// page, and correctly null for a standalone artifact, which no CSP governs.</summary>
    public static string RenderBody(ExecViewModel vm, string? chartJsHref, bool standalone, string? inlineChartJs = null, string? nonce = null)
    {
        // Rendered once here rather than at each of the four call sites below.
        var nonceAttr = string.IsNullOrEmpty(nonce)
            ? string.Empty
            : " nonce=\"" + HtmlEncoder.Default.Encode(nonce) + "\"";

        var d = vm.Dashboard;
        var h = HtmlEncoder.Default;
        var sb = new StringBuilder();

        sb.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurityInsight Analyzer - Executive view</title>
""");
        sb.Append("<style>").Append(Css).Append("</style>");
        sb.Append("</head><body>");

        // PIM-Manager-matched chrome: a blue brand bar + a tab strip below (same blue scheme,
        // layout and menu style as the PIM Manager, so SIA reads as a sibling product).
        sb.Append(NavChrome("exec", standalone));

        sb.Append("<main class=\"wrap\" role=\"main\">");

        // AUDIT #10: a partial read is stated BEFORE any figure. Every number below it is
        // understated, and an understated score reads as an IMPROVEMENT to anyone who does not
        // know. role="alert" so it is announced, not merely coloured.
        if (vm.Quality?.IsPartial == true)
        {
            sb.Append("<div class=\"partial-banner\" role=\"alert\"><strong>")
              .Append(h.Encode(SIAnalyzer.Web.Services.DataQuality.Warning))
              .Append("</strong>");
            if (!string.IsNullOrWhiteSpace(vm.Quality.Detail))
            {
                sb.Append(" <span class=\"partial-detail\">").Append(h.Encode(vm.Quality.Detail!)).Append("</span>");
            }
            sb.Append("</div>");
        }

        // Coverage & confidence banner.
        sb.Append("<div class=\"banner\" role=\"note\">");
        sb.Append(vm.IsLive ? "Live data" : "Demo data");
        sb.Append(" &middot; ").Append(vm.AiAvailable ? "AI narrative on" : "AI narrative unavailable (showing generated summary)");
        if (d.CurrentTime is not null)
        {
            sb.Append(" &middot; as of ").Append(h.Encode(d.CurrentTime.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
        }
        sb.Append("</div>");

        // One-sentence headline: the "if you read one thing" grounded verdict at the very
        // top - band + direction + the concrete count of actions to the next-better band.
        // The AI narrative (further down) narrates on top; this sentence is always present
        // (grounded, fail-soft) so the CIO sees a verdict even when AI is unavailable.
        var dirWord = d.Direction switch { "improving" => "improving", "worsening" => "needs attention", _ => "holding steady" };
        sb.Append("<h1 class=\"headline dir-").Append(d.Direction).Append("\">")
          .Append(h.Encode(d.Headline.Sentence)).Append("</h1>");

        // Hero row: score dial + direction + period-over-period.
        sb.Append("<section class=\"hero\" aria-label=\"Headline risk score\">");
        sb.Append("<div class=\"card dial-card\">");
        sb.Append("<div class=\"dial\"><canvas id=\"dial\" width=\"220\" height=\"220\" role=\"img\" aria-label=\"Overall risk score ")
          .Append(d.HeadlineScore.ToString(CultureInfo.InvariantCulture)).Append(", band ").Append(h.Encode(d.ScoreBand)).Append("\"></canvas>");
        sb.Append("<div class=\"dial-center\"><div class=\"dial-score\">").Append(d.HeadlineScore.ToString("0.#", CultureInfo.InvariantCulture)).Append("</div>");
        sb.Append("<div class=\"dial-band band-").Append(d.ScoreBand.ToLowerInvariant()).Append("\">").Append(h.Encode(d.ScoreBand)).Append("</div></div></div>");
        sb.Append("<div class=\"dial-caption\">Overall risk score</div></div>");

        sb.Append("<div class=\"card kpi-card\">");
        AppendKpi(sb, "Direction", DirArrow(d.ScoreDelta) + " " + dirWord, "dir-" + d.Direction);
        var pctText = d.PercentChange.HasValue ? (d.PercentChange.Value > 0 ? "+" : "") + d.PercentChange.Value.ToString("0.#", CultureInfo.InvariantCulture) + "% vs last snapshot" : "no prior snapshot";
        AppendKpi(sb, "Period-over-period", pctText, "");
        AppendKpi(sb, "New findings", d.NewCount.ToString(CultureInfo.InvariantCulture), d.NewCount > 0 ? "neg" : "pos");
        AppendKpi(sb, "Resolved", d.ClosedCount.ToString(CultureInfo.InvariantCulture), "pos");
        AppendKpi(sb, "Findings in scope", d.TotalFindings.ToString(CultureInfo.InvariantCulture), "");
        sb.Append("</div></section>");

        // Period-over-period: "since last board meeting" (configurable look-back).
        AppendPeriod(sb, d, h, standalone);

        // Executive summary (AI, grounded; or generated fallback - labelled).
        sb.Append("<section class=\"card summary\" aria-label=\"Executive summary\">");
        sb.Append("<h2>What this means</h2>");
        sb.Append("<p class=\"ai-note\">").Append(vm.SummaryFromAi ? "AI summary, grounded in the findings below." : "Generated summary (AI unavailable).").Append("</p>");
        sb.Append("<div class=\"summary-text\">").Append(ParaText(vm.ExecSummary, h)).Append("</div></section>");

        // Trend with labelled forecast.
        sb.Append("<section class=\"card\" aria-label=\"Risk trend over time\">");
        sb.Append("<h2>Are we getting safer?</h2>");
        sb.Append("<canvas id=\"trend\" height=\"110\" role=\"img\" aria-label=\"Risk score trend over time with a projected next point\"></canvas>");
        sb.Append("<p class=\"chart-cap\">The dashed point is a projection, not measured data.</p></section>");

        // Two donuts: severity + domain.
        sb.Append("<section class=\"grid2\">");
        sb.Append("<div class=\"card\"><h2>Where the risk sits (by severity)</h2><canvas id=\"sev\" height=\"180\" role=\"img\" aria-label=\"Risk by severity\"></canvas></div>");
        sb.Append("<div class=\"card\"><h2>Where the risk sits (by area)</h2><canvas id=\"dom\" height=\"180\" role=\"img\" aria-label=\"Risk by area\"></canvas></div>");
        sb.Append("</section>");

        // Risk concentration: where risk sits by area + where to invest.
        AppendConcentration(sb, d, h);

        // Trends & top movers: what improved/worsened most since the baseline snapshot.
        AppendTopMovers(sb, d, h);

        // Top risks + top wins.
        sb.Append("<section class=\"grid2\">");
        sb.Append("<div class=\"card\"><h2>Top risks right now</h2>").Append(RiskList(d.TopRisks, h, true)).Append("</div>");
        sb.Append("<div class=\"card\"><h2>Recent wins</h2>").Append(WinList(d, h)).Append("</div>");
        sb.Append("</section>");

        // "So what" - business-impact framing of the top risks.
        AppendBusinessImpact(sb, d, h);

        // Quick wins / ROI.
        sb.Append("<section class=\"card\" aria-label=\"Quick wins\">");
        sb.Append("<h2>Quickest wins (most risk removed per fix)</h2>");
        sb.Append("<table class=\"qw\"><thead><tr><th>Action</th><th>Why</th><th class=\"num\">Projected score drop</th><th>Urgency</th></tr></thead><tbody>");
        foreach (var q in d.QuickWins)
        {
            sb.Append("<tr><td>").Append(h.Encode(q.Title)).Append("</td><td>").Append(h.Encode(q.Plain))
              .Append("</td><td class=\"num\">-").Append(q.ProjectedScoreDrop.ToString("0.#", CultureInfo.InvariantCulture))
              .Append("</td><td><span class=\"urg urg-").Append(q.Urgency.Replace(" ", "").ToLowerInvariant()).Append("\">").Append(h.Encode(q.Urgency)).Append("</span></td></tr>");
        }
        sb.Append("</tbody></table><p class=\"chart-cap\">Projected drops assume each item is fully remediated; they are estimates, not guarantees.</p></section>");

        // Prioritised remediation plan: the next actions ranked by risk-removed-per-effort,
        // with the cumulative projected score + when the band improves.
        AppendRemediationPlan(sb, d, h);

        // Missing processes / org coaching: the leadership-level maturity gaps the finding
        // patterns imply (beyond per-asset fixes) - framed as processes/behaviours.
        AppendCoaching(sb, d, h);

        // Maturity scorecard + roadmap: where the environment and behaviour need to mature so
        // these findings stop coming back (rule-based rating per dimension + a "mature next" list).
        AppendMaturity(sb, d, h);

        // Framework lens: control-area rollup the board already reports against.
        AppendFrameworks(sb, d, h);

        // Aging / time-open: how long the worst risks have been open (accountability).
        AppendAging(sb, d, h);

        // Coverage & confidence detail.
        sb.Append("<section class=\"card\" aria-label=\"Coverage and confidence\">");
        sb.Append("<h2>How complete is this picture?</h2><div class=\"cov\">");
        foreach (var c in d.Coverage)
        {
            sb.Append("<div class=\"cov-item\"><div class=\"cov-top\"><span>").Append(h.Encode(c.Dimension)).Append("</span><strong>")
              .Append(c.Percent.ToString("0", CultureInfo.InvariantCulture)).Append("%</strong></div>");
            sb.Append("<div class=\"bar\"><div class=\"bar-fill\" style=\"width:").Append(c.Percent.ToString(CultureInfo.InvariantCulture)).Append("%\"></div></div>");
            sb.Append("<p class=\"cov-plain\">").Append(h.Encode(c.Plain)).Append("</p></div>");
        }
        sb.Append("</div></section>");

        // Drill-down on demand: the grounded evidence behind the headline score (no black box).
        AppendOverallEvidence(sb, d, h);

        // Plain-language glossary: "what these terms mean", collapsed by default to keep the
        // exec surface clean; present-now terms first, each with a grounded example.
        AppendGlossary(sb, d, h);

        // Print / export. The board-deck link opens the clean one-page PDF-friendly handout
        // (hosted only - the standalone preview has no server to serve /board).
        // AUDIT #13: was onclick="window.print()". An inline handler cannot be nonced -- keeping it
        // would have forced script-src 'unsafe-inline' on the whole app. Wired below instead.
        sb.Append("<div class=\"actions no-print\"><button type=\"button\" data-print=\"1\" class=\"btn\">Print / Save as PDF</button>");
        if (!standalone)
        {
            sb.Append(" <a href=\"/board\" class=\"btn btn-ghost\">Open board deck</a>");
        }
        sb.Append("</div>");

        sb.Append("</main>");

        // Data island for the charts (kept out of the prose so the page degrades cleanly).
        sb.Append("<script id=\"sianalyzer-data\" type=\"application/json\"").Append(nonceAttr).Append(">")
          .Append(JsonSerializer.Serialize(new
          {
              dialScore = d.HeadlineScore,
              dialMax = DialMax(d.HeadlineScore),
              band = d.ScoreBand,
              trend = d.Trend,
              severity = d.BySeverity,
              domain = d.ByDomain,
          }, Json))
          .Append("</script>");

        if (!string.IsNullOrEmpty(inlineChartJs))
        {
            sb.Append("<script").Append(nonceAttr).Append(">").Append(inlineChartJs).Append("</script>");
        }
        else
        {
            sb.Append("<script").Append(nonceAttr).Append(" src=\"").Append(h.Encode(chartJsHref ?? "/lib/chart.umd.js")).Append("\"></script>");
        }
        sb.Append("<script").Append(nonceAttr).Append(">").Append(ChartJsInit).Append("</script>");
        sb.Append(ScriptTag(PrintInit, nonce));
        sb.Append("</body></html>");
        return sb.ToString();
    }

    /// <summary>The PIM-Manager-matched chrome: a blue brand bar (uppercase title + sub) and a
    /// tab strip whose active tab is blue text + a blue underline - the SAME blue colour scheme,
    /// layout and menu style as the PIM Manager (tools/pim-manager). Shared by the exec view,
    /// the board deck and (via the static markup) the analyst surface so all three navigate like
    /// siblings of the Manager. Accessible: a real banner + a labelled nav with aria-current.</summary>
    internal static string NavChrome(string active, bool standalone)
    {
        var h = HtmlEncoder.Default;
        var sb = new StringBuilder();
        sb.Append("<header class=\"brandbar\" role=\"banner\"><div class=\"brand\">")
          .Append("<span class=\"logo\" aria-hidden=\"true\">SI</span>")
          .Append("<span class=\"brand-title\">SecurityInsight Analyzer</span>")
          .Append("<span class=\"brand-sub\">Executive security posture</span></div></header>");

        sb.Append("<nav class=\"tabs\" aria-label=\"Surfaces\">");
        if (standalone)
        {
            sb.Append("<span class=\"tab active\" aria-current=\"page\">Executive</span>");
            sb.Append("<span class=\"tab-note\">Preview</span>");
        }
        else
        {
            void Tab(string key, string href, string label)
            {
                var isActive = key == active;
                sb.Append("<a class=\"tab").Append(isActive ? " active" : "").Append("\" href=\"").Append(h.Encode(href)).Append("\"");
                if (isActive) sb.Append(" aria-current=\"page\"");
                sb.Append(">").Append(h.Encode(label)).Append("</a>");
            }
            Tab("exec", "/exec", "Executive");
            Tab("board", "/board", "Board deck");
            Tab("analyst", "/analyst", "Analyst");
            Tab("governance", "/governance", "Governance");
        }
        sb.Append("</nav>");
        return sb.ToString();
    }

    private static void AppendKpi(StringBuilder sb, string label, string value, string cls)
    {
        sb.Append("<div class=\"kpi\"><div class=\"kpi-label\">").Append(HtmlEncoder.Default.Encode(label))
          .Append("</div><div class=\"kpi-value ").Append(cls).Append("\">").Append(HtmlEncoder.Default.Encode(value)).Append("</div></div>");
    }

    private static string RiskList(IReadOnlyList<SIAnalyzer.Core.Model.RiskRow> rows, HtmlEncoder h, bool risk)
    {
        if (rows.Count == 0) return "<p class=\"muted\">Nothing notable.</p>";
        var sb = new StringBuilder("<ul class=\"rlist\">");
        foreach (var r in rows)
        {
            sb.Append("<li><div class=\"rl-top\"><span class=\"rl-name\">").Append(h.Encode(r.ConfigurationName))
              .Append("</span><span class=\"sev sev-").Append((r.SecuritySeverity ?? "").ToLowerInvariant()).Append("\">").Append(h.Encode(r.SecuritySeverity ?? "")).Append("</span></div>");
            sb.Append("<div class=\"rl-why\">").Append(h.Encode(string.IsNullOrEmpty(r.RiskFactorConsequence) ? r.RiskFactorProbability : r.RiskFactorConsequence)).Append("</div></li>");
        }
        sb.Append("</ul>");
        return sb.ToString();
    }

    private static string WinList(ExecDashboard d, HtmlEncoder h)
    {
        if (d.TopWins.Count == 0)
        {
            return d.ClosedCount > 0
                ? $"<p class=\"muted\">{d.ClosedCount} finding(s) resolved since the last snapshot.</p>"
                : "<p class=\"muted\">No improvements recorded since the last snapshot.</p>";
        }
        var sb = new StringBuilder("<ul class=\"rlist\">");
        foreach (var r in d.TopWins)
        {
            sb.Append("<li><div class=\"rl-top\"><span class=\"rl-name\">").Append(h.Encode(r.ConfigurationName))
              .Append("</span><span class=\"sev sev-improved\">improved</span></div>");
            sb.Append("<div class=\"rl-why\">").Append(h.Encode(r.RiskFactorProbability)).Append("</div></li>");
        }
        sb.Append("</ul>");
        return sb.ToString();
    }

    /// <summary>Prioritised remediation plan: the "next N actions" ranked by risk-removed-per-
    /// effort (ROI). Each row groups all of one asset's findings into a single fix with its
    /// projected score drop, an effort estimate, a plain recommendation, and the running
    /// cumulative score after doing it; a summary line states where the plan lands + the
    /// band-crossing count. Plain language; every number grounded; effort/ROI labelled estimates.</summary>
    private static void AppendRemediationPlan(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var p = d.Remediation;
        if (p.Actions.Count == 0) return;
        sb.Append("<section class=\"card\" aria-label=\"Prioritised remediation plan\">");
        sb.Append("<h2>Your next moves (biggest risk removed per unit of effort)</h2>");

        // Summary line: where the shown plan lands + the band-crossing achievement.
        sb.Append("<p class=\"plan-line\">Doing these <strong>").Append(p.Actions.Count.ToString(CultureInfo.InvariantCulture))
          .Append("</strong> action").Append(p.Actions.Count == 1 ? "" : "s").Append(" is projected to take your overall risk from <strong>")
          .Append(p.StartScore.ToString("0.#", CultureInfo.InvariantCulture)).Append("</strong> (").Append(h.Encode(p.StartBand))
          .Append(") to <strong>").Append(p.ProjectedScoreAfterPlan.ToString("0.#", CultureInfo.InvariantCulture)).Append("</strong> (")
          .Append(h.Encode(p.ProjectedBandAfterPlan)).Append(").");
        if (p.NextBetterBand is not null && p.BandCrossActionCount is { } bc)
        {
            sb.Append(" The first <strong>").Append(bc.ToString(CultureInfo.InvariantCulture)).Append("</strong> move")
              .Append(bc == 1 ? "" : "s").Append(" alone would move you to <span class=\"pos\">").Append(h.Encode(p.NextBetterBand)).Append("</span>.");
        }
        sb.Append("</p>");

        sb.Append("<table class=\"qw plan\"><thead><tr><th>#</th><th>Action</th><th>Area</th><th>Effort</th>")
          .Append("<th class=\"num\">Risk removed</th><th class=\"num\">Score after</th></tr></thead><tbody>");
        foreach (var a in p.Actions)
        {
            sb.Append("<tr><td class=\"plan-rank\">").Append(a.Rank.ToString(CultureInfo.InvariantCulture)).Append("</td>");
            sb.Append("<td><div class=\"plan-title\">").Append(h.Encode(a.Recommendation)).Append("</div>");
            sb.Append("<div class=\"plan-asset\">").Append(h.Encode(a.ConfigurationName));
            sb.Append(" &middot; <span class=\"sev sev-").Append((a.TopSeverity ?? "").ToLowerInvariant()).Append("\">").Append(h.Encode(a.TopSeverity ?? "")).Append("</span>");
            if (a.FindingCount > 1)
            {
                sb.Append(" &middot; ").Append(a.FindingCount.ToString(CultureInfo.InvariantCulture)).Append(" findings");
            }
            sb.Append("</div><div class=\"plan-why\">").Append(h.Encode(a.Why)).Append("</div></td>");
            sb.Append("<td>").Append(h.Encode(a.AreaPlain)).Append("</td>");
            sb.Append("<td><span class=\"eff eff-").Append((a.Effort ?? "").ToLowerInvariant()).Append("\">").Append(h.Encode(a.Effort ?? "")).Append("</span></td>");
            sb.Append("<td class=\"num\">-").Append(a.ProjectedScoreDrop.ToString("0.#", CultureInfo.InvariantCulture)).Append("</td>");
            sb.Append("<td class=\"num plan-after\">").Append(a.CumulativeScoreAfter.ToString("0.#", CultureInfo.InvariantCulture));
            if (a.CrossesBandHere)
            {
                sb.Append(" <span class=\"band-cross\">&rarr; ").Append(h.Encode(a.BandAfter)).Append("</span>");
            }
            sb.Append("</td></tr>");
        }
        sb.Append("</tbody></table>");
        sb.Append("<p class=\"chart-cap\">Ranked by risk removed per unit of effort. \"Risk removed\" is the sum of the asset's finding scores (the exact amount your overall score drops if it is fully remediated); \"Score after\" is the running total once that action and the ones above it are done. Effort is an estimate from the findings, not an hours or cost figure.</p></section>");
    }

    /// <summary>Framework lens: one card with a tab-free, print-friendly block per framework
    /// (NIST CSF / CIS / ISO 27001), each a small bar list of control-area scores. Plain
    /// language only; the score is a grounded partition of the headline number.</summary>
    private static void AppendFrameworks(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        if (d.Frameworks.Count == 0) return;
        sb.Append("<section class=\"card\" aria-label=\"Framework lens\">");
        sb.Append("<h2>How does this map to the frameworks you report on?</h2>");
        sb.Append("<div class=\"fw\">");
        foreach (var fw in d.Frameworks)
        {
            // Scale bars within the framework so the biggest area fills the bar.
            var maxScore = fw.Areas.Count > 0 ? Math.Max(1, fw.Areas.Max(a => a.Score)) : 1;
            sb.Append("<div class=\"fw-block\"><h3 class=\"fw-name\">").Append(h.Encode(fw.Framework)).Append("</h3>");
            if (fw.Areas.Count == 0)
            {
                sb.Append("<p class=\"muted\">No findings to map.</p>");
            }
            foreach (var a in fw.Areas)
            {
                var widthPct = Math.Round(a.Score / maxScore * 100, 1);
                sb.Append("<div class=\"fw-row\"><div class=\"fw-top\"><span class=\"fw-area\">").Append(h.Encode(a.Area))
                  .Append("</span><strong class=\"fw-score\">").Append(a.Score.ToString("0.#", CultureInfo.InvariantCulture)).Append("</strong></div>");
                sb.Append("<div class=\"bar\"><div class=\"bar-fill\" style=\"width:").Append(widthPct.ToString(CultureInfo.InvariantCulture)).Append("%\"></div></div>");
                sb.Append("<p class=\"fw-plain\">").Append(h.Encode(a.Plain)).Append(" <span class=\"muted\">(")
                  .Append(a.Findings.ToString(CultureInfo.InvariantCulture)).Append(a.Findings == 1 ? " finding" : " findings").Append(")</span></p></div>");
            }
            sb.Append("</div>");
        }
        sb.Append("</div><p class=\"chart-cap\">Each control-area score is the risk from the findings that map to it; the areas add up to your overall score. High-level mapping, not a per-control audit.</p></section>");
    }

    /// <summary>Missing processes / org coaching: the leadership-level maturity gaps the
    /// finding PATTERNS imply (privileged-access reviews, exposure reviews, patch cadence,
    /// onboarding, ownership, crown-jewel protection). Each is framed as a recommended
    /// process/behaviour - never a per-asset ticket - with the grounded evidence count + the
    /// example assets behind it. When no systemic gap stands out it says so honestly rather
    /// than inventing one. Plain language only.</summary>
    private static void AppendCoaching(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var cv = d.Coaching;
        sb.Append("<section class=\"card\" aria-label=\"Processes worth strengthening\">");
        sb.Append("<h2>Processes worth strengthening</h2>");
        sb.Append("<p class=\"coach-intro\">Beyond fixing individual assets, these are the organisational habits the patterns point to - leadership-level, not technical tickets.</p>");

        if (!cv.HasGaps)
        {
            sb.Append("<p class=\"muted\">No systemic process gap stands out across the ")
              .Append(cv.AssetsConsidered.ToString(CultureInfo.InvariantCulture))
              .Append(cv.AssetsConsidered == 1 ? " asset" : " assets")
              .Append(" in scope - the findings look like one-offs rather than a missing process. Keep the current cadence.</p></section>");
            return;
        }

        sb.Append("<ul class=\"coach-list\">");
        foreach (var g in cv.Gaps)
        {
            sb.Append("<li class=\"coach-item\"><div class=\"coach-top\"><span class=\"coach-theme\">").Append(h.Encode(g.Theme)).Append("</span>");
            sb.Append("<span class=\"coach-count\">").Append(g.AffectedAssets.ToString(CultureInfo.InvariantCulture))
              .Append(g.AffectedAssets == 1 ? " asset" : " assets").Append("</span></div>");
            sb.Append("<p class=\"coach-find\">").Append(h.Encode(g.Finding)).Append("</p>");
            sb.Append("<p class=\"coach-rec\"><span class=\"coach-rec-label\">Recommended:</span> ").Append(h.Encode(g.Recommendation)).Append("</p></li>");
        }
        sb.Append("</ul>");
        sb.Append("<p class=\"chart-cap\">Each habit is inferred from a pattern across multiple findings - the count and the example assets are taken straight from your current data; the recommendation is a process, not a single fix. Nothing here is invented.</p></section>");
    }

    /// <summary>Maturity scorecard + roadmap: a leader-facing capability rating per dimension
    /// (Tiering, Privileged Access, Identity Hygiene, Exposure Management, Visibility &amp;
    /// Coverage, Operating Discipline), each a rule-based 0-100 maturity score (higher = better)
    /// with a plain band, plus a prioritised "mature here next" roadmap. Dimensions with no
    /// in-scope asset are honestly shown as "not enough data"; the roadmap is omitted when no
    /// dimension stands out. Plain language only - the score is a grounded partition of the real
    /// rows, nothing invented.</summary>
    private static void AppendMaturity(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var m = d.Maturity;
        sb.Append("<section class=\"card\" aria-label=\"Security maturity scorecard\">");
        sb.Append("<h2>Where do we need to mature?</h2>");
        sb.Append("<p class=\"coach-intro\">A capability rating across the disciplines that stop findings coming back - higher is more mature. ");
        if (m.OverallScore is { } ov)
        {
            sb.Append("Overall maturity is <strong>").Append(ov.ToString("0", CultureInfo.InvariantCulture))
              .Append("/100 (").Append(h.Encode(m.OverallRating)).Append(")</strong>, averaged across the dimensions with data.");
        }
        else
        {
            sb.Append("Not enough data yet to rate maturity.");
        }
        sb.Append("</p>");

        sb.Append("<div class=\"mat\">");
        foreach (var dim in m.Dimensions)
        {
            sb.Append("<div class=\"mat-row\"><div class=\"mat-top\"><span class=\"mat-dim\">").Append(h.Encode(dim.Dimension)).Append("</span>");
            if (dim.HasData)
            {
                sb.Append("<strong class=\"mat-score\">").Append(dim.Score.ToString("0", CultureInfo.InvariantCulture))
                  .Append("/100 <span class=\"mat-band mat-band-").Append(dim.Rating.Replace(" ", "").ToLowerInvariant()).Append("\">")
                  .Append(h.Encode(dim.Rating)).Append("</span></strong></div>");
                sb.Append("<div class=\"bar\"><div class=\"bar-fill\" style=\"width:").Append(dim.Score.ToString(CultureInfo.InvariantCulture)).Append("%\"></div></div>");
                sb.Append("<p class=\"mat-plain\">").Append(h.Encode(dim.Plain)).Append(" <span class=\"muted\">(")
                  .Append(dim.WeakAssets.ToString(CultureInfo.InvariantCulture)).Append(" of ").Append(dim.Considered.ToString(CultureInfo.InvariantCulture))
                  .Append(dim.Considered == 1 ? " in-scope asset" : " in-scope assets").Append(" need attention)</span></p></div>");
            }
            else
            {
                sb.Append("<strong class=\"mat-score muted\">Not enough data</strong></div>");
                sb.Append("<p class=\"mat-plain\">").Append(h.Encode(dim.Plain))
                  .Append(" <span class=\"muted\">(no in-scope assets in the current snapshot)</span></p></div>");
            }
        }
        sb.Append("</div>");

        if (m.HasRoadmap)
        {
            sb.Append("<h3 class=\"mat-roadmap-h\">Mature here next</h3>");
            sb.Append("<ol class=\"mat-roadmap\">");
            foreach (var dim in m.Roadmap)
            {
                sb.Append("<li class=\"mat-move\"><span class=\"mat-move-dim\">").Append(h.Encode(dim.Dimension))
                  .Append("</span> <span class=\"muted\">(").Append(dim.Score.ToString("0", CultureInfo.InvariantCulture))
                  .Append("/100, ").Append(dim.WeakAssets.ToString(CultureInfo.InvariantCulture))
                  .Append(dim.WeakAssets == 1 ? " asset" : " assets").Append(")</span>");
                sb.Append("<p class=\"mat-move-rec\">").Append(h.Encode(dim.NextMove)).Append("</p></li>");
            }
            sb.Append("</ol>");
        }
        else
        {
            sb.Append("<p class=\"muted\">No dimension stands out as a systemic gap right now - keep the current cadence.</p>");
        }

        sb.Append("<p class=\"chart-cap\">Each maturity score is the share of in-scope assets WITHOUT a weakness in that discipline, taken straight from your current data - higher is more mature. The roadmap lists the disciplines with the most room to improve. Nothing here is invented; dimensions with no in-scope assets are shown as \"not enough data\".</p></section>");
    }

    /// <summary>Aging / time-open: a small table of the worst risks with how long each has been
    /// open + a headline average. All dates come from the snapshot history (grounded).</summary>
    private static void AppendAging(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var ag = d.Aging;
        if (ag.Items.Count == 0) return;
        sb.Append("<section class=\"card\" aria-label=\"How long risks have been open\">");
        sb.Append("<h2>How long have the top risks been open?</h2>");
        sb.Append("<div class=\"age-kpis\">");
        AppendKpi(sb, "Average time open", ag.AverageDaysOpen.ToString("0.#", CultureInfo.InvariantCulture) + (ag.AverageDaysOpen == 1 ? " day" : " days"), "");
        AppendKpi(sb, "Longest open", ag.LongestDaysOpen.ToString(CultureInfo.InvariantCulture) + (ag.LongestDaysOpen == 1 ? " day" : " days"), ag.LongestDaysOpen > 0 ? "neg" : "");
        AppendKpi(sb, "Carried over", ag.CarriedOverCount.ToString(CultureInfo.InvariantCulture), ag.CarriedOverCount > 0 ? "neg" : "pos");
        AppendKpi(sb, "New this period", ag.NewThisSnapshotCount.ToString(CultureInfo.InvariantCulture), "");
        sb.Append("</div>");
        sb.Append("<table class=\"qw\"><thead><tr><th>Risk</th><th>Severity</th><th class=\"num\">Days open</th><th>Open since</th></tr></thead><tbody>");
        foreach (var i in ag.Items)
        {
            sb.Append("<tr><td>").Append(h.Encode(i.ConfigurationName)).Append("</td>");
            sb.Append("<td><span class=\"sev sev-").Append((i.SecuritySeverity ?? "").ToLowerInvariant()).Append("\">").Append(h.Encode(i.SecuritySeverity ?? "")).Append("</span></td>");
            sb.Append("<td class=\"num\">").Append(i.DaysOpen.ToString(CultureInfo.InvariantCulture));
            if (i.IsNew) sb.Append(" <span class=\"badge-new\">new</span>");
            sb.Append("</td><td>").Append(h.Encode(i.OpenSince.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))).Append("</td></tr>");
        }
        sb.Append("</tbody></table><p class=\"chart-cap\">Time-open is measured from the first snapshot in which each risk has continuously appeared, up to the latest snapshot.</p></section>");
    }

    /// <summary>Period-over-period panel ("since last board meeting"): a plain-language
    /// comparison of the latest posture against a baseline snapshot chosen by a
    /// configurable look-back window, with a period selector. All counts are grounded in
    /// the snapshot diff; the selector is hidden in the static preview (no live server).</summary>
    private static void AppendPeriod(StringBuilder sb, ExecDashboard d, HtmlEncoder h, bool standalone)
    {
        var p = d.Period;
        sb.Append("<section class=\"card\" aria-label=\"Period-over-period comparison\">");
        sb.Append("<div class=\"period-head\"><h2>").Append(h.Encode(p.Period.Label)).Append("</h2>");

        // Period selector (live only - the links re-request /exec?period=...).
        if (!standalone)
        {
            sb.Append("<div class=\"period-pick no-print\" role=\"group\" aria-label=\"Choose reporting period\">");
            foreach (var preset in SIAnalyzer.Core.Analysis.ReportingPeriod.Presets)
            {
                var active = preset.Key == p.Period.Key ? " active" : "";
                sb.Append("<a class=\"chip").Append(active).Append("\" href=\"/exec?period=")
                  .Append(h.Encode(preset.Key)).Append("\">").Append(h.Encode(ShortPeriod(preset.Key))).Append("</a>");
            }
            sb.Append("</div>");
        }
        sb.Append("</div>");

        if (!p.HasBaseline)
        {
            sb.Append("<p class=\"muted\">Only one snapshot so far - a period comparison needs at least two. Everything below is current as of the first run.</p></section>");
            return;
        }

        // Plain "since X" framing line.
        var dirWord = p.Diff.ScoreDelta < 0 ? "down" : p.Diff.ScoreDelta > 0 ? "up" : "unchanged";
        var dirCls = p.Diff.ScoreDelta < 0 ? "pos" : p.Diff.ScoreDelta > 0 ? "neg" : "";
        sb.Append("<p class=\"period-line\">Compared with <strong>")
          .Append(h.Encode(p.BaselineTime!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)))
          .Append("</strong> (").Append(p.DaysSpanned.ToString(CultureInfo.InvariantCulture))
          .Append(p.DaysSpanned == 1 ? " day ago" : " days ago").Append("), your overall risk is <span class=\"")
          .Append(dirCls).Append("\">").Append(dirWord);
        if (p.Diff.ScoreDelta != 0)
        {
            sb.Append(" ").Append(Math.Abs(p.Diff.ScoreDelta).ToString("0.#", CultureInfo.InvariantCulture)).Append(" points");
        }
        sb.Append("</span>.</p>");

        if (!p.BaselineExact)
        {
            sb.Append("<p class=\"chart-cap\">No snapshot existed exactly that far back yet, so the earliest available snapshot is used as the baseline.</p>");
        }

        sb.Append("<div class=\"period-kpis\">");
        AppendKpi(sb, "New since then", p.Diff.NewCount.ToString(CultureInfo.InvariantCulture), p.Diff.NewCount > 0 ? "neg" : "pos");
        AppendKpi(sb, "Resolved since then", p.Diff.ClosedCount.ToString(CultureInfo.InvariantCulture), "pos");
        AppendKpi(sb, "Got worse", p.Diff.RegressedCount.ToString(CultureInfo.InvariantCulture), p.Diff.RegressedCount > 0 ? "neg" : "");
        AppendKpi(sb, "Improved", p.Diff.ImprovedCount.ToString(CultureInfo.InvariantCulture), "pos");
        sb.Append("</div>");
        sb.Append("<p class=\"chart-cap\">Counts compare the latest snapshot against the snapshot at the start of this period - grounded in the data, nothing projected.</p></section>");
    }

    private static string ShortPeriod(string key) => key switch
    {
        "previous" => "Last snapshot",
        "month" => "Month",
        "quarter" => "Quarter",
        "half" => "Half-year",
        "year" => "Year",
        _ => key,
    };

    /// <summary>Risk-concentration panel: where the risk sits by area (identity vs endpoint
    /// vs cloud), each with its share of the total, period direction, and the single biggest
    /// contributor - the "where do we invest" steer. Plain language; grounded in the rows.</summary>
    private static void AppendConcentration(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var c = d.Concentration;
        if (c.Areas.Count == 0) return;
        sb.Append("<section class=\"card\" aria-label=\"Where risk concentrates\">");
        sb.Append("<h2>Where does the risk concentrate?</h2>");
        var maxScore = Math.Max(1, c.Areas.Max(a => a.Score));
        sb.Append("<div class=\"conc\">");
        foreach (var a in c.Areas)
        {
            var widthPct = Math.Round(a.Score / maxScore * 100, 1);
            sb.Append("<div class=\"conc-row\"><div class=\"conc-top\"><span class=\"conc-area\">").Append(h.Encode(a.Plain))
              .Append("</span><span class=\"conc-share\">").Append(a.SharePercent.ToString("0.#", CultureInfo.InvariantCulture)).Append("% of risk</span></div>");
            sb.Append("<div class=\"bar\"><div class=\"bar-fill\" style=\"width:").Append(widthPct.ToString(CultureInfo.InvariantCulture)).Append("%\"></div></div>");
            sb.Append("<p class=\"conc-plain\"><span class=\"dir-").Append(a.Direction).Append("\">");
            sb.Append(a.Direction switch { "improving" => "improving", "worsening" => "rising", _ => "steady" });
            if (a.ChangePercent.HasValue)
            {
                sb.Append(" (").Append(a.ChangePercent.Value > 0 ? "+" : "").Append(a.ChangePercent.Value.ToString("0.#", CultureInfo.InvariantCulture)).Append("%)");
            }
            sb.Append("</span> &middot; ").Append(a.Findings.ToString(CultureInfo.InvariantCulture)).Append(a.Findings == 1 ? " finding" : " findings")
              .Append(" &middot; biggest: ").Append(h.Encode(a.TopContributor)).Append("</p></div>");
        }
        sb.Append("</div>");
        if (c.MostConcentratedArea is not null && c.Areas.Count > 0)
        {
            sb.Append("<p class=\"invest\">Most risk sits in <strong>").Append(h.Encode(c.Areas[0].Plain))
              .Append("</strong> - the area to direct investment first.</p>");
        }
        sb.Append("<p class=\"chart-cap\">Each area's share is its part of the overall risk score; the shares add up to your total. Direction is versus the period baseline above.</p></section>");
    }

    /// <summary>Trends &amp; top movers: which areas improved/worsened the MOST since the
    /// baseline snapshot, plus a per-lens breakdown (area / severity / tier). Answers the
    /// board question "what moved?" in plain language. When only one snapshot exists it says
    /// so honestly rather than implying a trend. All deltas are grounded score sums.</summary>
    private static void AppendTopMovers(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var m = d.Movers;
        sb.Append("<section class=\"card\" aria-label=\"What moved the most\">");
        sb.Append("<h2>What moved the most?</h2>");

        if (!m.HasComparison)
        {
            sb.Append("<p class=\"muted\">Only one snapshot so far - there is nothing to compare against yet. ")
              .Append("Top movers will appear once a second run has been collected.</p></section>");
            return;
        }

        // Headline line: overall direction since the baseline.
        var dirCls = m.TotalDelta < 0 ? "pos" : m.TotalDelta > 0 ? "neg" : "";
        var dirWord = m.TotalDelta < 0 ? "down" : m.TotalDelta > 0 ? "up" : "unchanged";
        sb.Append("<p class=\"movers-line\">Since <strong>")
          .Append(h.Encode((m.BaselineTime ?? d.CurrentTime!.Value).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)))
          .Append("</strong>, overall risk is <span class=\"").Append(dirCls).Append("\">").Append(dirWord);
        if (m.TotalDelta != 0)
        {
            sb.Append(" ").Append(Math.Abs(m.TotalDelta).ToString("0.#", CultureInfo.InvariantCulture)).Append(" points");
        }
        sb.Append("</span>.</p>");

        // Two columns: biggest improvements vs biggest regressions (by area).
        sb.Append("<div class=\"movers2\">");
        sb.Append("<div class=\"mover-col\"><h3 class=\"mover-h pos\">Biggest improvements</h3>")
          .Append(MoverList(m.BiggestImprovements, h, improved: true)).Append("</div>");
        sb.Append("<div class=\"mover-col\"><h3 class=\"mover-h neg\">Biggest increases</h3>")
          .Append(MoverList(m.BiggestRegressions, h, improved: false)).Append("</div>");
        sb.Append("</div>");

        // Per-lens detail (area / severity / tier) behind a clean reveal.
        sb.Append("<details class=\"movers-detail\"><summary><span class=\"drill-q\">Break it down by area, severity and tier</span></summary>");
        foreach (var g in m.Groups)
        {
            var shown = g.Moves.Where(x => x.Direction != "steady").Take(6).ToList();
            if (shown.Count == 0) continue;
            sb.Append("<div class=\"mover-grp\"><h4 class=\"mover-grp-h\">").Append(h.Encode(g.Plain)).Append("</h4><ul class=\"mover-rows\">");
            foreach (var x in shown)
            {
                var cls = x.Direction == "improving" ? "pos" : x.Direction == "worsening" ? "neg" : "";
                var arrow = x.Delta < 0 ? "↓" : x.Delta > 0 ? "↑" : "→";
                sb.Append("<li><span class=\"mover-name\">").Append(h.Encode(x.Plain)).Append("</span>")
                  .Append("<span class=\"mover-delta ").Append(cls).Append("\">").Append(arrow).Append(" ")
                  .Append((x.Delta > 0 ? "+" : "")).Append(x.Delta.ToString("0.#", CultureInfo.InvariantCulture));
                if (x.ChangePercent.HasValue)
                {
                    sb.Append(" (").Append(x.ChangePercent.Value > 0 ? "+" : "").Append(x.ChangePercent.Value.ToString("0.#", CultureInfo.InvariantCulture)).Append("%)");
                }
                sb.Append("</span></li>");
            }
            sb.Append("</ul></div>");
        }
        sb.Append("</details>");
        sb.Append("<p class=\"chart-cap\">Each number is the change in summed risk score for that group since the baseline snapshot - grounded in the data, nothing projected.</p></section>");
    }

    private static string MoverList(IReadOnlyList<DimensionMove> moves, HtmlEncoder h, bool improved)
    {
        if (moves.Count == 0)
        {
            return improved
                ? "<p class=\"muted\">No area improved since the baseline.</p>"
                : "<p class=\"muted\">No area got worse since the baseline.</p>";
        }
        var sb = new StringBuilder("<ul class=\"mover-rows\">");
        foreach (var x in moves)
        {
            var cls = improved ? "pos" : "neg";
            var arrow = improved ? "↓" : "↑";
            sb.Append("<li><span class=\"mover-name\">").Append(h.Encode(x.Plain)).Append("</span>")
              .Append("<span class=\"mover-delta ").Append(cls).Append("\">").Append(arrow).Append(" ")
              .Append((x.Delta > 0 ? "+" : "")).Append(x.Delta.ToString("0.#", CultureInfo.InvariantCulture));
            if (x.ChangePercent.HasValue)
            {
                sb.Append(" (").Append(x.ChangePercent.Value > 0 ? "+" : "").Append(x.ChangePercent.Value.ToString("0.#", CultureInfo.InvariantCulture)).Append("%)");
            }
            sb.Append("</span></li>");
        }
        sb.Append("</ul>");
        return sb.ToString();
    }

    /// <summary>"So what" business-impact panel: each top risk re-stated as a plain-language
    /// business consequence (data exposure / downtime / compliance / reputation) with the
    /// grounded technical driver behind it. No KQL/jargon; consequence KIND only, never an
    /// invented cost or probability figure.</summary>
    private static void AppendBusinessImpact(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var bi = d.BusinessImpact;
        if (bi.Items.Count == 0) return;
        sb.Append("<section class=\"card\" aria-label=\"What this means for the business\">");
        sb.Append("<h2>So what? What this means for the business</h2>");

        // Category summary chips (where the consequence concentrates).
        if (bi.ByCategory.Count > 0)
        {
            sb.Append("<div class=\"bi-cats\">");
            foreach (var c in bi.ByCategory)
            {
                sb.Append("<span class=\"bi-cat bi-").Append(c.Label.Replace(" ", "").ToLowerInvariant()).Append("\">")
                  .Append(h.Encode(c.Label)).Append(" <strong>").Append(c.Value.ToString("0", CultureInfo.InvariantCulture)).Append("</strong></span>");
            }
            sb.Append("</div>");
        }

        sb.Append("<ul class=\"bi-list\">");
        foreach (var i in bi.Items)
        {
            sb.Append("<li><div class=\"bi-top\"><span class=\"bi-name\">").Append(h.Encode(i.ConfigurationName)).Append("</span>");
            sb.Append("<span class=\"bi-cat bi-").Append(i.Category.Replace(" ", "").ToLowerInvariant()).Append("\">").Append(h.Encode(i.Category)).Append("</span></div>");
            sb.Append("<p class=\"bi-cons\">").Append(h.Encode(i.Consequence)).Append("</p>");
            sb.Append("<p class=\"bi-why\"><span class=\"muted\">Based on:</span> ").Append(h.Encode(i.Why)).Append("</p></li>");
        }
        sb.Append("</ul>");
        sb.Append("<p class=\"chart-cap\">Each line is the business consequence if the finding is exploited - the kind of impact, grounded in the finding itself. No cost or likelihood is implied.</p></section>");
    }

    /// <summary>Drill-down on demand: a collapsed, accessible reveal of the actual findings
    /// that SUM to the headline score - so no number on this page is a black box. The detail
    /// is grounded analyst evidence (real rows), hidden by default to keep the exec surface
    /// clean.</summary>
    private static void AppendOverallEvidence(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var dd = d.OverallEvidence;
        if (dd.Items.Count == 0) return;
        sb.Append("<details class=\"card drill\"><summary><span class=\"drill-q\">Show me the detail behind the score</span>");
        sb.Append("<span class=\"muted\"> &middot; top ").Append(dd.Items.Count.ToString(CultureInfo.InvariantCulture))
          .Append(" of ").Append(dd.ContributorCount.ToString(CultureInfo.InvariantCulture)).Append(" findings</span></summary>");
        sb.Append("<table class=\"qw\"><thead><tr><th>Finding</th><th>Area</th><th>Severity</th><th class=\"num\">Score</th><th class=\"num\">Share</th></tr></thead><tbody>");
        foreach (var i in dd.Items)
        {
            sb.Append("<tr><td>").Append(h.Encode(i.ConfigurationName)).Append("</td>");
            sb.Append("<td>").Append(h.Encode(i.SecurityDomain)).Append("</td>");
            sb.Append("<td><span class=\"sev sev-").Append((i.SecuritySeverity ?? "").ToLowerInvariant()).Append("\">").Append(h.Encode(i.SecuritySeverity ?? "")).Append("</span></td>");
            sb.Append("<td class=\"num\">").Append(i.RiskScoreTotal.ToString("0.#", CultureInfo.InvariantCulture)).Append("</td>");
            sb.Append("<td class=\"num\">").Append(i.SharePercent.ToString("0.#", CultureInfo.InvariantCulture)).Append("%</td></tr>");
        }
        sb.Append("</tbody></table>");
        sb.Append("<p class=\"chart-cap\">These are the actual findings behind your overall score of ")
          .Append(dd.Total.ToString("0.#", CultureInfo.InvariantCulture))
          .Append("; the shown rows account for ").Append(dd.ShownScore.ToString("0.#", CultureInfo.InvariantCulture))
          .Append(" of it. Open the Analyst view for the full evidence.</p></details>");
    }

    /// <summary>Plain-language glossary ("what these terms mean"): a clean, collapsed-by-
    /// default reveal that defines every security term used on this page for a non-technical
    /// reader. Present-now terms are shown first with a small "in your data now" badge and a
    /// GROUNDED example from the real rows; absent terms are still defined and honestly
    /// marked "not in your current data". No invented numbers - it never fabricates an
    /// example.</summary>
    private static void AppendGlossary(StringBuilder sb, ExecDashboard d, HtmlEncoder h)
    {
        var g = d.Glossary;
        if (g.Terms.Count == 0) return;
        sb.Append("<details class=\"card glos\"><summary><span class=\"drill-q\">What do these terms mean?</span>");
        sb.Append("<span class=\"muted\"> &middot; plain-language guide</span></summary>");
        sb.Append("<dl class=\"glos-list\">");
        foreach (var t in g.Terms)
        {
            sb.Append("<div class=\"glos-item").Append(t.Present ? " present" : "").Append("\">");
            sb.Append("<dt class=\"glos-term\">").Append(h.Encode(t.Term));
            if (t.Present)
            {
                sb.Append(" <span class=\"glos-badge\">in your data now</span>");
            }
            sb.Append("</dt>");
            sb.Append("<dd class=\"glos-def\">").Append(h.Encode(t.Plain));
            sb.Append("<div class=\"glos-eg").Append(t.Present ? "" : " glos-absent").Append("\">")
              .Append(h.Encode(t.InYourData)).Append("</div></dd>");
            sb.Append("</div>");
        }
        sb.Append("</dl>");
        sb.Append("<p class=\"chart-cap\">Every example is taken straight from your current findings; terms not present in your data are still defined but clearly marked so nothing is invented.</p></details>");
    }

    private static string ParaText(string text, HtmlEncoder h)
    {
        var paras = (text ?? "").Replace("\r", "").Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
        if (paras.Length == 0) return "<p>" + h.Encode(text ?? "") + "</p>";
        return string.Concat(paras.Select(p => "<p>" + h.Encode(p.Trim()).Replace("\n", "<br>") + "</p>"));
    }

    private static string DirArrow(double delta) => delta < 0 ? "↓" : delta > 0 ? "↑" : "→";
    private static double DialMax(double score) => Math.Max(100, Math.Ceiling((score + 1) / 100) * 100);

    /// <summary>The shared PIM-blue theme CSS, exposed so sibling surfaces (e.g. the
    /// governance page) render with the identical look/chrome.</summary>
    internal static string ThemeCss => Css;

    // PIM-Manager-matched theme: the SAME blue colour scheme (#0969da), light surfaces,
    // tab-strip menu and layout as tools/pim-manager, so SIA reads as a sibling of the
    // Manager. Mobile-first (works at ~360px, no fixed widths that overflow) + accessible
    // (WCAG-AA contrast on text, semantic headings/landmarks, visible :focus-visible ring,
    // a skip-target). Charts (Chart.js) are recoloured to the light palette in ChartJsInit.
    private const string Css = """
:root{--bg:#ffffff;--card:#ffffff;--surface:#f6f8fa;--ink:#1a1a1a;--muted:#57606a;--line:#d0d7de;
--accent:#0969da;--accent-dk:#0a53be;--accent-soft:#ddf4ff;
--crit:#cf222e;--high:#bc4c00;--med:#9a6700;--low:#1a7f37;--good:#1a7f37;--bad:#cf222e;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,system-ui,Arial,sans-serif;background:var(--surface);color:var(--ink);line-height:1.5}
a{color:var(--accent)}
a:focus-visible,button:focus-visible,summary:focus-visible,.tab:focus-visible,.chip:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.brandbar{background:var(--accent);color:#fff;padding:12px 20px;position:sticky;top:0;z-index:6}
.brand{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.logo{background:#fff;color:var(--accent);border-radius:6px;padding:3px 8px;font-weight:800;font-size:14px}
.brand-title{font-weight:700;font-size:17px;letter-spacing:.4px;text-transform:uppercase}
.brand-sub{font-size:11px;opacity:.9}
.tabs{display:flex;flex-wrap:wrap;gap:2px;background:var(--surface);border-bottom:1px solid var(--line);padding:0 12px;position:sticky;top:48px;z-index:5}
.tab{padding:11px 16px;cursor:pointer;font-size:13px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:2px solid transparent;white-space:nowrap}
.tab:hover{color:var(--accent)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-note{margin-left:auto;align-self:center;color:var(--muted);font-size:12px;padding:0 6px}
.wrap{max-width:1080px;margin:0 auto;padding:20px}
.banner{font-size:13px;color:var(--muted);background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin-bottom:18px}
.partial-banner{font-size:14px;background:rgba(207,34,46,.10);border:2px solid var(--crit);color:#8b1a1a;border-radius:8px;padding:12px 14px;margin-bottom:14px}
.partial-detail{display:block;font-size:12px;margin-top:4px;color:#6a1414}
.headline{font-size:clamp(20px,4vw,32px);font-weight:800;margin:6px 0 22px;line-height:1.25}
.dir-improving{color:var(--good)}.dir-worsening{color:var(--bad)}.dir-steady{color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:18px}
.card h2{font-size:16px;margin:0 0 14px;color:var(--ink)}
.hero{display:grid;grid-template-columns:280px 1fr;gap:18px}
.dial-card{display:flex;flex-direction:column;align-items:center;justify-content:center}
.dial{position:relative;width:220px;height:220px;max-width:100%}
.dial-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.dial-score{font-size:44px;font-weight:800}
.dial-band{font-weight:700;border-radius:20px;padding:2px 14px;margin-top:4px;font-size:14px}
.band-low{background:rgba(26,127,55,.12);color:var(--low)}.band-moderate{background:rgba(154,103,0,.12);color:var(--med)}
.band-elevated{background:rgba(188,76,0,.12);color:var(--high)}.band-severe{background:rgba(207,34,46,.12);color:var(--crit)}
.dial-caption{color:var(--muted);font-size:13px;margin-top:10px}
.kpi-card{display:grid;grid-template-columns:repeat(2,1fr);gap:14px 22px;align-content:center}
.kpi-label{color:var(--muted);font-size:13px}
.kpi-value{font-size:22px;font-weight:700}
.kpi-value.pos{color:var(--good)}.kpi-value.neg{color:var(--bad)}
.summary .ai-note{color:var(--muted);font-size:12px;margin:-6px 0 10px}
.summary-text p{margin:0 0 10px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
canvas{max-width:100%}
.chart-cap{color:var(--muted);font-size:12px;margin:10px 0 0}
.rlist{list-style:none;margin:0;padding:0}
.rlist li{padding:10px 0;border-bottom:1px solid var(--line)}.rlist li:last-child{border:0}
.rl-top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.rl-name{font-weight:600}.rl-why{color:var(--muted);font-size:13px;margin-top:2px}
.sev{font-size:11px;font-weight:700;border-radius:14px;padding:2px 10px;white-space:nowrap}
.sev-critical{background:rgba(207,34,46,.12);color:var(--crit)}.sev-high{background:rgba(188,76,0,.12);color:var(--high)}
.sev-medium{background:rgba(154,103,0,.12);color:var(--med)}.sev-low{background:rgba(26,127,55,.12);color:var(--low)}
.sev-improved{background:rgba(26,127,55,.12);color:var(--good)}
.qw{width:100%;border-collapse:collapse;font-size:14px}
.qw th,.qw td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
.qw th{color:var(--muted);font-weight:600}.qw .num{text-align:right;color:var(--good);font-weight:700}
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
.urg{font-size:11px;font-weight:700;border-radius:12px;padding:2px 9px}
.urg-now{background:rgba(207,34,46,.12);color:var(--crit)}.urg-thisweek{background:rgba(188,76,0,.12);color:var(--high)}.urg-thismonth{background:var(--accent-soft);color:var(--accent-dk)}
.plan-line{margin:0 0 14px}.plan-line .pos{color:var(--good);font-weight:700}
.plan-rank{font-weight:800;color:var(--accent);text-align:center;width:28px}
.plan-title{font-weight:600}.plan-asset{color:var(--muted);font-size:12px;margin-top:2px}.plan-why{color:var(--muted);font-size:12px;margin-top:2px}
.plan .plan-after{color:var(--ink)}
.eff{font-size:11px;font-weight:700;border-radius:12px;padding:2px 9px;white-space:nowrap}
.eff-low{background:rgba(26,127,55,.12);color:var(--low)}.eff-medium{background:rgba(154,103,0,.12);color:var(--med)}.eff-high{background:rgba(188,76,0,.12);color:var(--high)}
.band-cross{color:var(--good);font-weight:700;font-size:12px;white-space:nowrap}
.cov{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.cov-top{display:flex;justify-content:space-between;font-size:14px}
.bar{height:8px;background:var(--surface);border:1px solid var(--line);border-radius:6px;overflow:hidden;margin:6px 0}
.bar-fill{height:100%;background:var(--accent)}
.cov-plain{color:var(--muted);font-size:12px;margin:4px 0 0}
.fw{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.fw-name{font-size:14px;margin:0 0 10px;color:var(--ink)}
.fw-row{margin:0 0 10px}
.fw-top{display:flex;justify-content:space-between;font-size:13px}
.fw-area{font-weight:600}.fw-score{color:var(--accent)}
.fw-plain{color:var(--muted);font-size:12px;margin:3px 0 0}
.coach-intro{color:var(--muted);font-size:13px;margin:-6px 0 14px}
.coach-list{list-style:none;margin:0;padding:0}
.coach-item{padding:14px 0;border-bottom:1px solid var(--line)}.coach-item:last-child{border:0}
.coach-top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.coach-theme{font-weight:700;font-size:14px}
.coach-count{font-size:11px;font-weight:700;border-radius:14px;padding:2px 10px;background:rgba(188,76,0,.12);color:var(--high);white-space:nowrap}
.coach-find{margin:6px 0 4px;font-size:13px}
.coach-rec{margin:0;color:var(--muted);font-size:13px}
.coach-rec-label{color:var(--accent);font-weight:700}
.mat{margin:0 0 6px}
.mat-row{margin:0 0 12px}
.mat-top{display:flex;justify-content:space-between;align-items:center;font-size:14px;gap:10px;flex-wrap:wrap}
.mat-dim{font-weight:600}.mat-score{color:var(--ink);white-space:nowrap}
.mat-band{font-size:10px;font-weight:700;border-radius:10px;padding:1px 8px;margin-left:6px}
.mat-band-managed{background:rgba(26,127,55,.12);color:var(--good)}
.mat-band-defined{background:var(--accent-soft);color:var(--accent-dk)}
.mat-band-developing{background:rgba(188,76,0,.12);color:var(--high)}
.mat-band-initial{background:rgba(207,34,46,.12);color:var(--crit)}
.mat-plain{color:var(--muted);font-size:12px;margin:4px 0 0}
.mat-roadmap-h{font-size:14px;margin:16px 0 8px}
.mat-roadmap{margin:0;padding:0 0 0 20px}
.mat-move{margin:0 0 10px}
.mat-move-dim{font-weight:700;font-size:13px}
.mat-move-rec{margin:3px 0 0;color:var(--muted);font-size:13px}
.age-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px 22px;margin:0 0 14px}
.badge-new{font-size:10px;font-weight:700;border-radius:10px;padding:1px 7px;background:rgba(188,76,0,.12);color:var(--high);margin-left:4px}
.period-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.period-head h2{margin:0}
.period-pick{display:flex;flex-wrap:wrap;gap:6px}
.chip{color:var(--accent);text-decoration:none;border:1px solid var(--line);background:#fff;border-radius:20px;padding:4px 12px;font-size:12px;font-weight:600}
.chip:hover{border-color:var(--accent)}
.chip.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.period-line{margin:12px 0 4px}.period-line .pos{color:var(--good);font-weight:700}.period-line .neg{color:var(--bad);font-weight:700}
.period-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px 22px;margin:10px 0 0}
.conc-row{margin:0 0 12px}
.conc-top{display:flex;justify-content:space-between;font-size:14px}
.conc-area{font-weight:600}.conc-share{color:var(--accent);font-weight:600}
.conc-plain{color:var(--muted);font-size:12px;margin:3px 0 0}
.invest{font-size:13px;margin:4px 0 0}
.movers-line{margin:0 0 14px}.movers-line .pos{color:var(--good);font-weight:700}.movers-line .neg{color:var(--bad);font-weight:700}
.movers2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.mover-h{font-size:13px;margin:0 0 8px}.mover-h.pos{color:var(--good)}.mover-h.neg{color:var(--bad)}
.mover-rows{list-style:none;margin:0;padding:0}
.mover-rows li{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)}.mover-rows li:last-child{border:0}
.mover-name{font-weight:600;font-size:14px}
.mover-delta{font-size:13px;font-weight:700;white-space:nowrap}.mover-delta.pos{color:var(--good)}.mover-delta.neg{color:var(--bad)}
.movers-detail{margin:14px 0 0}
.movers-detail>summary{cursor:pointer;font-weight:600;color:var(--accent);list-style:none}
.movers-detail>summary::-webkit-details-marker{display:none}
.movers-detail>summary::before{content:"\25B8";margin-right:8px}
.movers-detail[open]>summary::before{content:"\25BE"}
.mover-grp{margin:12px 0 0}.mover-grp-h{font-size:13px;margin:0 0 4px;color:var(--ink)}
.bi-cats{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 14px}
.bi-cat{font-size:11px;font-weight:700;border-radius:14px;padding:2px 10px;white-space:nowrap}
.bi-dataexposure{background:rgba(207,34,46,.12);color:var(--crit)}
.bi-downtime{background:rgba(188,76,0,.12);color:var(--high)}
.bi-compliance{background:var(--accent-soft);color:var(--accent-dk)}
.bi-reputation{background:rgba(130,80,223,.12);color:#8250df}
.bi-list{list-style:none;margin:0;padding:0}
.bi-list li{padding:12px 0;border-bottom:1px solid var(--line)}.bi-list li:last-child{border:0}
.bi-top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.bi-name{font-weight:600}
.bi-cons{margin:6px 0 4px}
.bi-why{color:var(--muted);font-size:12px;margin:0}
.drill{padding:0}
.drill>summary{cursor:pointer;padding:16px 20px;font-weight:600;list-style:none}
.drill>summary::-webkit-details-marker{display:none}
.drill>summary::before{content:"\25B8";margin-right:8px;color:var(--accent)}
.drill[open]>summary::before{content:"\25BE"}
.drill .drill-q{color:var(--accent)}
.drill .qw{margin:0 20px;width:calc(100% - 40px)}
.drill .tbl-wrap{margin:0 20px}.drill .tbl-wrap .qw{margin:0;width:100%}
.drill .chart-cap{padding:0 20px 16px}
.glos{padding:0}
.glos>summary{cursor:pointer;padding:16px 20px;font-weight:600;list-style:none}
.glos>summary::-webkit-details-marker{display:none}
.glos>summary::before{content:"\25B8";margin-right:8px;color:var(--accent)}
.glos[open]>summary::before{content:"\25BE"}
.glos .drill-q{color:var(--accent)}
.glos-list{margin:0;padding:0 20px}
.glos-item{padding:12px 0;border-bottom:1px solid var(--line)}.glos-item:last-child{border:0}
.glos-term{font-weight:700;font-size:14px}
.glos-badge{font-size:10px;font-weight:700;border-radius:10px;padding:1px 8px;background:rgba(26,127,55,.12);color:var(--good);margin-left:6px;vertical-align:middle}
.glos-def{margin:4px 0 0;color:var(--ink);font-size:13px}
.glos-eg{margin:6px 0 0;color:var(--muted);font-size:12px;border-left:2px solid var(--accent);padding-left:10px}
.glos-eg.glos-absent{border-left-color:var(--line);font-style:italic}
.glos .chart-cap{padding:0 20px 16px}
.muted{color:var(--muted)}
.actions{text-align:center;margin:8px 0 30px}
.btn{display:inline-block;background:var(--accent);color:#fff;border:0;border-radius:8px;padding:10px 18px;font-weight:700;cursor:pointer;text-decoration:none}
.btn:hover{background:var(--accent-dk)}
.btn-ghost{background:#fff;color:var(--accent);border:1px solid var(--accent);margin-left:8px}
@media (max-width:760px){.hero{grid-template-columns:1fr}.grid2{grid-template-columns:1fr}.cov{grid-template-columns:1fr}.kpi-card{grid-template-columns:1fr 1fr}.fw{grid-template-columns:1fr}.age-kpis{grid-template-columns:1fr 1fr}.period-kpis{grid-template-columns:1fr 1fr}.movers2{grid-template-columns:1fr}}
@media (max-width:420px){.wrap{padding:14px}.card{padding:16px}.tabs{top:46px}.brand-sub{flex-basis:100%}.kpi-card,.age-kpis,.period-kpis{grid-template-columns:1fr 1fr}.dial-score{font-size:38px}}
@media print{body{background:#fff;color:#111}.brandbar,.tabs,.no-print{display:none}.card{border:1px solid #ccc;break-inside:avoid}.banner{color:#444}}
""";

    /// <summary>
    /// AUDIT #13: replaces <c>onclick="window.print()"</c> on the exec view and the board deck.
    /// Deliberately its OWN script rather than a few lines inside <see cref="ChartJsInit"/>, which
    /// returns early when Chart.js is absent - folding it in there would have made the print button
    /// stop working on any page without charts, which is exactly the kind of silent breakage a
    /// green test suite cannot see.
    /// </summary>
    internal const string PrintInit = """
(function(){
  document.querySelectorAll('[data-print]').forEach(function(b){
    b.addEventListener('click',function(){window.print();});
  });
})();
""";

    /// <summary>Wraps a script body in a &lt;script&gt; tag carrying the CSP nonce (audit #13).
    /// A null/empty nonce emits a plain tag - correct for standalone artifacts, which no CSP
    /// governs. Shared so the exec view, the board deck and the governance page cannot drift.</summary>
    internal static string ScriptTag(string body, string? nonce)
    {
        var attr = string.IsNullOrEmpty(nonce)
            ? string.Empty
            : " nonce=\"" + HtmlEncoder.Default.Encode(nonce) + "\"";
        return "<script" + attr + ">" + body + "</script>";
    }

    // Light (PIM-blue) chart palette: matches the CSS theme (#0969da accent, GitHub-style
    // status colours), readable on the white surfaces.
    private const string ChartJsInit = """
(function(){
  var dataEl=document.getElementById('sianalyzer-data');
  if(!dataEl||typeof Chart==='undefined')return;
  var D=JSON.parse(dataEl.textContent);
  var ink='#1a1a1a',grid='#d0d7de';
  var sevColors={Critical:'#cf222e',High:'#bc4c00',Medium:'#9a6700',Low:'#1a7f37',Unknown:'#57606a'};
  var palette=['#0969da','#1a7f37','#bc4c00','#9a6700','#cf222e','#8250df'];
  function bandColor(b){return {Low:'#1a7f37',Moderate:'#9a6700',Elevated:'#bc4c00',Severe:'#cf222e'}[b]||'#0969da';}
  // Dial (doughnut gauge).
  var dc=document.getElementById('dial');
  if(dc){new Chart(dc,{type:'doughnut',data:{datasets:[{data:[D.dialScore,Math.max(0,D.dialMax-D.dialScore)],
    backgroundColor:[bandColor(D.band),'#eaeef2'],borderWidth:0,circumference:270,rotation:225}]},
    options:{cutout:'80%',plugins:{legend:{display:false},tooltip:{enabled:false}},responsive:false}});}
  // Trend (line; forecast point dashed).
  var tc=document.getElementById('trend');
  if(tc&&D.trend){var labels=D.trend.map(function(p){return p.date;});
    var vals=D.trend.map(function(p){return p.score;});
    var pointStyle=D.trend.map(function(p){return p.isForecast?'rectRot':'circle';});
    new Chart(tc,{type:'line',data:{labels:labels,datasets:[{label:'Risk score',data:vals,
      borderColor:'#0969da',backgroundColor:'rgba(9,105,218,.10)',fill:true,tension:.25,
      pointStyle:pointStyle,pointRadius:5,
      segment:{borderDash:function(ctx){return D.trend[ctx.p1DataIndex]&&D.trend[ctx.p1DataIndex].isForecast?[6,5]:undefined;}}}]},
      options:{plugins:{legend:{display:false}},scales:{x:{ticks:{color:ink},grid:{color:grid}},y:{beginAtZero:true,ticks:{color:ink},grid:{color:grid}}}}});}
  function donut(id,arr,colorFn){var el=document.getElementById(id);if(!el||!arr)return;
    new Chart(el,{type:'doughnut',data:{labels:arr.map(function(s){return s.label;}),
      datasets:[{data:arr.map(function(s){return s.value;}),backgroundColor:arr.map(colorFn),borderColor:'#ffffff',borderWidth:2}]},
      options:{cutout:'62%',plugins:{legend:{position:'right',labels:{color:ink,boxWidth:12}}}}});}
  donut('sev',D.severity,function(s){return sevColors[s.label]||'#57606a';});
  donut('dom',D.domain,function(s,i){return palette[D.domain.indexOf(s)%palette.length];});
})();
""";
}
