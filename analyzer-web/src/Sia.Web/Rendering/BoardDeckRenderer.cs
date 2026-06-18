using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using Sia.Core.Exec;
using Sia.Web.Services;

namespace Sia.Web.Rendering;

/// <summary>
/// Renders the BOARD-DECK export: a clean, single-page, print/PDF-friendly executive
/// handout (REQUIREMENTS.md "SI Analyzer": "Board-deck export ... one-click PDF handout").
/// Unlike the interactive exec dashboard this view is deliberately:
/// <list type="bullet">
///   <item>ONE page - the few things a board reads: the headline verdict, the score+band,
///   the direction since last period, the top risks, the recent wins, where the risk
///   concentrates, the business consequence kinds, and the recommended next actions.</item>
///   <item>Print-first - light theme, no canvas/JS charts, page-break-safe, so "Print /
///   Save as PDF" yields a tidy handout.</item>
///   <item>Self-contained - inline CSS only, no external CDN, so it opens/prints anywhere.</item>
/// </list>
/// Every figure is the SAME grounded number the dashboard shows (it consumes the identical
/// <see cref="ExecDashboard"/>); nothing is recomputed, invented, or fabricated. No KQL,
/// no jargon, no cost/likelihood figures - only consequence KIND and concrete action counts.
/// </summary>
public static class BoardDeckRenderer
{
    /// <summary>Render the complete one-page board-deck document for the given exec view.</summary>
    public static string Render(ExecViewModel vm)
    {
        var d = vm.Dashboard;
        var hl = d.Headline;
        var h = HtmlEncoder.Default;
        var sb = new StringBuilder();
        var asOf = d.CurrentTime?.ToString("d MMMM yyyy", CultureInfo.InvariantCulture) ?? "latest snapshot";

        sb.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurityInsight Analyzer - Board summary</title>
""");
        sb.Append("<style>").Append(Css).Append("</style>");
        sb.Append("</head><body>");
        sb.Append("<main class=\"deck\">");

        // --- Header: title + as-of + source/AI honesty line ---------------------
        sb.Append("<header class=\"deck-head\">");
        sb.Append("<div><h1>Security posture - board summary</h1>");
        sb.Append("<p class=\"sub\">As of ").Append(h.Encode(asOf)).Append(" &middot; ")
          .Append(vm.IsLive ? "live data" : "demo data").Append("</p></div>");
        sb.Append("<div class=\"badge band-").Append(hl.Band.ToLowerInvariant()).Append("\"><span class=\"badge-score\">")
          .Append(hl.Score.ToString("0.#", CultureInfo.InvariantCulture)).Append("</span><span class=\"badge-band\">")
          .Append(h.Encode(hl.Band)).Append("</span></div>");
        sb.Append("</header>");

        // --- The one-sentence verdict (the "if you read one thing") -------------
        sb.Append("<section class=\"verdict dir-").Append(hl.Direction).Append("\">")
          .Append(h.Encode(hl.Sentence)).Append("</section>");

        // --- KPI strip: direction, period-over-period, new/resolved ------------
        sb.Append("<section class=\"kpis\">");
        Kpi(sb, h, "Direction", DirArrow(d.ScoreDelta) + " " + DirWord(d.Direction));
        var pct = d.PercentChange.HasValue
            ? (d.PercentChange.Value > 0 ? "+" : "") + d.PercentChange.Value.ToString("0.#", CultureInfo.InvariantCulture) + "% vs last snapshot"
            : "no prior snapshot";
        Kpi(sb, h, "Period-over-period", pct);
        Kpi(sb, h, "New findings", d.NewCount.ToString(CultureInfo.InvariantCulture));
        Kpi(sb, h, "Resolved", d.ClosedCount.ToString(CultureInfo.InvariantCulture));
        Kpi(sb, h, "Findings in scope", d.TotalFindings.ToString(CultureInfo.InvariantCulture));
        sb.Append("</section>");

        // --- Executive summary (grounded; AI on top or templated fallback) -----
        sb.Append("<section class=\"block\"><h2>What this means</h2>");
        sb.Append("<div class=\"prose\">").Append(ParaText(vm.ExecSummary, h)).Append("</div></section>");

        // --- Two columns: top risks | recent wins ------------------------------
        sb.Append("<section class=\"cols\">");
        sb.Append("<div class=\"block\"><h2>Top risks right now</h2>");
        sb.Append(RiskList(d, h));
        sb.Append("</div>");
        sb.Append("<div class=\"block\"><h2>Recent wins</h2>");
        sb.Append(WinList(d, h));
        sb.Append("</div></section>");

        // --- Where risk concentrates (top areas) -------------------------------
        if (d.Concentration.Areas.Count > 0)
        {
            sb.Append("<section class=\"block\"><h2>Where the risk concentrates</h2><ul class=\"areas\">");
            foreach (var a in d.Concentration.Areas.Take(4))
            {
                sb.Append("<li><span class=\"area-name\">").Append(h.Encode(a.Plain)).Append("</span>")
                  .Append("<span class=\"area-share\">").Append(a.SharePercent.ToString("0.#", CultureInfo.InvariantCulture))
                  .Append("% of risk</span></li>");
            }
            sb.Append("</ul></section>");
        }

        // --- Business consequence kinds (the "so what" categories) -------------
        if (d.BusinessImpact.ByCategory.Count > 0)
        {
            sb.Append("<section class=\"block\"><h2>What is at stake (kind of consequence)</h2><div class=\"cats\">");
            foreach (var c in d.BusinessImpact.ByCategory)
            {
                sb.Append("<span class=\"cat\">").Append(h.Encode(c.Label)).Append(" <strong>")
                  .Append(c.Value.ToString("0", CultureInfo.InvariantCulture)).Append("</strong></span>");
            }
            sb.Append("</div><p class=\"cap\">Counts are findings by the kind of business consequence if exploited - no cost or likelihood is implied.</p></section>");
        }

        // --- Recommended next actions (the prioritised remediation plan) -------
        var plan = d.Remediation;
        if (plan.Actions.Count > 0)
        {
            sb.Append("<section class=\"block\"><h2>Recommended next actions</h2>");
            sb.Append("<p class=\"plan-line\">These ").Append(plan.Actions.Count.ToString(CultureInfo.InvariantCulture))
              .Append(" moves are projected to take overall risk from <strong>").Append(plan.StartScore.ToString("0.#", CultureInfo.InvariantCulture))
              .Append("</strong> (").Append(h.Encode(plan.StartBand)).Append(") to <strong>")
              .Append(plan.ProjectedScoreAfterPlan.ToString("0.#", CultureInfo.InvariantCulture)).Append("</strong> (")
              .Append(h.Encode(plan.ProjectedBandAfterPlan)).Append(").");
            if (plan.NextBetterBand is not null && plan.BandCrossActionCount is { } bc)
            {
                sb.Append(" The first ").Append(bc.ToString(CultureInfo.InvariantCulture)).Append(" alone reach <strong>")
                  .Append(h.Encode(plan.NextBetterBand)).Append("</strong>.");
            }
            sb.Append("</p><ol class=\"actions\">");
            foreach (var a in plan.Actions.Take(5))
            {
                sb.Append("<li><span class=\"act-title\">").Append(h.Encode(a.Recommendation)).Append("</span>")
                  .Append(" <span class=\"act-meta\">").Append(h.Encode(a.ConfigurationName)).Append(" &middot; ")
                  .Append(h.Encode(a.Effort)).Append(" effort &middot; removes ")
                  .Append(a.ProjectedScoreDrop.ToString("0.#", CultureInfo.InvariantCulture)).Append(" points</span></li>");
            }
            sb.Append("</ol><p class=\"cap\">Ranked by risk removed per unit of effort; projected drops assume full remediation and are estimates (no cost or date implied).</p></section>");
        }

        // --- Processes worth strengthening (org coaching, the systemic view) ----
        var coaching = d.Coaching;
        if (coaching.HasGaps)
        {
            sb.Append("<section class=\"block\"><h2>Processes worth strengthening</h2>");
            sb.Append("<p class=\"plan-line\">Beyond individual fixes, the patterns point to these organisational habits:</p>");
            sb.Append("<ul class=\"coach\">");
            foreach (var g in coaching.Gaps.Take(4))
            {
                sb.Append("<li><span class=\"coach-theme\">").Append(h.Encode(g.Theme)).Append("</span> ")
                  .Append("<span class=\"coach-meta\">(").Append(g.AffectedAssets.ToString(CultureInfo.InvariantCulture))
                  .Append(g.AffectedAssets == 1 ? " asset" : " assets").Append(")</span>");
                sb.Append("<div class=\"coach-rec\">").Append(h.Encode(g.Recommendation)).Append("</div></li>");
            }
            sb.Append("</ul><p class=\"cap\">Inferred from patterns across multiple findings; framed as a process, not a single fix - nothing invented.</p></section>");
        }

        // --- Footer: honesty + print button ------------------------------------
        sb.Append("<footer class=\"deck-foot\">");
        sb.Append("<span>").Append(vm.SummaryFromAi ? "Summary written by AI, grounded in the findings." : "Summary generated from the findings (AI unavailable).").Append("</span>");
        sb.Append("<span class=\"foot-src\">SecurityInsight Analyzer</span>");
        sb.Append("</footer>");

        sb.Append("<div class=\"no-print toolbar\"><button onclick=\"window.print()\" class=\"btn\">Print / Save as PDF</button> ");
        sb.Append("<a href=\"/exec\" class=\"btn ghost\">Back to dashboard</a></div>");

        sb.Append("</main></body></html>");
        return sb.ToString();
    }

    private static void Kpi(StringBuilder sb, HtmlEncoder h, string label, string value)
    {
        sb.Append("<div class=\"kpi\"><div class=\"kpi-l\">").Append(h.Encode(label))
          .Append("</div><div class=\"kpi-v\">").Append(h.Encode(value)).Append("</div></div>");
    }

    private static string RiskList(ExecDashboard d, HtmlEncoder h)
    {
        var rows = d.TopRisks.Take(3).ToList();
        if (rows.Count == 0) return "<p class=\"muted\">Nothing notable.</p>";
        var sb = new StringBuilder("<ul class=\"rlist\">");
        foreach (var r in rows)
        {
            sb.Append("<li><div class=\"rl-top\"><span class=\"rl-name\">").Append(h.Encode(r.ConfigurationName))
              .Append("</span><span class=\"sev sev-").Append((r.SecuritySeverity ?? "").ToLowerInvariant()).Append("\">")
              .Append(h.Encode(r.SecuritySeverity ?? "")).Append("</span></div>");
            sb.Append("<div class=\"rl-why\">").Append(h.Encode(string.IsNullOrEmpty(r.RiskFactorConsequence) ? r.RiskFactorProbability : r.RiskFactorConsequence))
              .Append("</div></li>");
        }
        sb.Append("</ul>");
        return sb.ToString();
    }

    private static string WinList(ExecDashboard d, HtmlEncoder h)
    {
        var rows = d.TopWins.Take(3).ToList();
        if (rows.Count == 0)
        {
            return d.ClosedCount > 0
                ? $"<p class=\"muted\">{d.ClosedCount} finding(s) resolved since the last snapshot.</p>"
                : "<p class=\"muted\">No improvements recorded since the last snapshot.</p>";
        }
        var sb = new StringBuilder("<ul class=\"rlist\">");
        foreach (var r in rows)
        {
            sb.Append("<li><div class=\"rl-top\"><span class=\"rl-name\">").Append(h.Encode(r.ConfigurationName))
              .Append("</span><span class=\"sev sev-improved\">improved</span></div>");
            sb.Append("<div class=\"rl-why\">").Append(h.Encode(r.RiskFactorProbability)).Append("</div></li>");
        }
        sb.Append("</ul>");
        return sb.ToString();
    }

    private static string ParaText(string text, HtmlEncoder h)
    {
        var paras = (text ?? "").Replace("\r", "").Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
        if (paras.Length == 0) return "<p>" + h.Encode(text ?? "") + "</p>";
        return string.Concat(paras.Select(p => "<p>" + h.Encode(p.Trim()).Replace("\n", "<br>") + "</p>"));
    }

    private static string DirArrow(double delta) => delta < 0 ? "↓" : delta > 0 ? "↑" : "→";
    private static string DirWord(string dir) => dir switch { "improving" => "improving", "worsening" => "worsening", _ => "steady" };

    // Light, print-first theme (no charts, page-break-safe). Self-contained.
    private const string Css = """
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,Roboto,system-ui,Arial,sans-serif;background:#eef1f5;color:#1c2733;line-height:1.45}
.deck{max-width:820px;margin:0 auto;padding:28px;background:#fff}
.deck-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;border-bottom:2px solid #1c2733;padding-bottom:14px}
.deck-head h1{font-size:24px;margin:0}
.sub{color:#5a6b7d;font-size:13px;margin:4px 0 0}
.badge{display:flex;flex-direction:column;align-items:center;border-radius:12px;padding:8px 18px;min-width:108px}
.badge-score{font-size:30px;font-weight:800;line-height:1}
.badge-band{font-size:13px;font-weight:700;margin-top:2px}
.band-low{background:#e3f7ee;color:#1a7a4f}.band-moderate{background:#fff6da;color:#9a7400}
.band-elevated{background:#fff0df;color:#b5650f}.band-severe{background:#fde4e4;color:#b51f1f}
.verdict{font-size:19px;font-weight:700;margin:18px 0;padding:14px 18px;border-radius:10px;background:#f4f7fa;border-left:5px solid #4ea1ff}
.verdict.dir-improving{border-left-color:#1a7a4f}.verdict.dir-worsening{border-left-color:#b51f1f}.verdict.dir-steady{border-left-color:#4ea1ff}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:0 0 18px}
.kpi{background:#f4f7fa;border:1px solid #dde4ec;border-radius:10px;padding:10px 12px}
.kpi-l{color:#5a6b7d;font-size:12px}.kpi-v{font-size:16px;font-weight:700;margin-top:2px}
.block{margin:0 0 16px}
.block h2{font-size:15px;margin:0 0 8px;color:#1c2733;border-bottom:1px solid #dde4ec;padding-bottom:4px}
.prose p{margin:0 0 8px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.rlist{list-style:none;margin:0;padding:0}
.rlist li{padding:8px 0;border-bottom:1px solid #eef1f5}.rlist li:last-child{border:0}
.rl-top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.rl-name{font-weight:600}.rl-why{color:#5a6b7d;font-size:12px;margin-top:2px}
.sev{font-size:10px;font-weight:700;border-radius:12px;padding:2px 9px;white-space:nowrap}
.sev-critical{background:#fde4e4;color:#b51f1f}.sev-high{background:#fff0df;color:#b5650f}
.sev-medium{background:#fff6da;color:#9a7400}.sev-low{background:#e3f7ee;color:#1a7a4f}.sev-improved{background:#e3f7ee;color:#1a7a4f}
.areas{list-style:none;margin:0;padding:0}
.areas li{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #eef1f5}.areas li:last-child{border:0}
.area-name{font-weight:600}.area-share{color:#4a5a6b}
.cats{display:flex;flex-wrap:wrap;gap:8px}
.cat{font-size:12px;font-weight:600;border:1px solid #dde4ec;border-radius:14px;padding:3px 12px;background:#f4f7fa}
.actions{margin:0;padding-left:20px}
.actions li{padding:4px 0}
.act-title{font-weight:600}.act-urg{color:#b5650f;font-size:12px;font-weight:700;margin-left:6px}
.act-meta{color:#5a6b7d;font-size:12px;margin-left:6px}
.plan-line{margin:0 0 10px;font-size:13px}
.coach{list-style:none;margin:0;padding:0}
.coach li{padding:7px 0;border-bottom:1px solid #eef1f5}.coach li:last-child{border:0}
.coach-theme{font-weight:700}.coach-meta{color:#5a6b7d;font-size:12px}
.coach-rec{color:#3a4a5b;font-size:12px;margin-top:2px}
.cap{color:#7a8a9b;font-size:11px;margin:8px 0 0}
.muted{color:#7a8a9b}
.deck-foot{display:flex;justify-content:space-between;font-size:11px;color:#7a8a9b;border-top:1px solid #dde4ec;margin-top:18px;padding-top:10px}
.toolbar{text-align:center;margin:18px 0 6px}
.btn{display:inline-block;background:#4ea1ff;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:700;cursor:pointer;text-decoration:none;font-size:14px}
.btn.ghost{background:#fff;color:#1c2733;border:1px solid #b9c4d0}
@media (max-width:680px){.kpis{grid-template-columns:1fr 1fr}.cols{grid-template-columns:1fr}}
@media print{
  body{background:#fff}
  .deck{max-width:none;padding:0}
  .no-print{display:none}
  .block,.cols,.kpis,.verdict{break-inside:avoid}
  @page{margin:16mm}
}
""";
}
