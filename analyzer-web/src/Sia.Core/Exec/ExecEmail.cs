using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// The grounded exec-summary EMAIL message - subject + an email-safe HTML body + a
/// plain-text alternative - rendered from the SAME grounded exec dashboard the GUI and
/// the board deck use (REQUIREMENTS.md "SI Analyzer": "scheduled monthly email ... so
/// the CIO gets it without opening the tool").
///
/// It is the short "if you read one thing" digest: the one-sentence headline verdict,
/// the score + band, the period direction, the top risks and the recommended next
/// actions - plus a link to the full board deck. Every figure is the SAME grounded
/// number the dashboard shows; nothing is recomputed, invented, or fabricated. No KQL,
/// no jargon, no cost/likelihood - consequence KIND only.
/// </summary>
public sealed record ExecEmailMessage(string Subject, string HtmlBody, string TextBody);

/// <summary>
/// Pure renderer for the exec-summary email. No network, no AI call, no secrets - it
/// consumes an already-built exec view (whose narrative is already AI-on-or-templated)
/// and turns it into an email message. Inline-CSS, table-based HTML so it survives the
/// common mail clients (Outlook/Gmail); a plain-text twin is always produced too.
/// </summary>
public static class ExecEmailRenderer
{
    /// <summary>
    /// Render the exec-summary email from the grounded dashboard + narrative.
    /// </summary>
    /// <param name="headline">The "if you read one thing" verdict (grounded).</param>
    /// <param name="dashboard">The grounded exec dashboard (all figures come from here).</param>
    /// <param name="execSummary">The narrative paragraph (AI-on or templated fallback).</param>
    /// <param name="summaryFromAi">Whether the narrative came from AI (honesty line).</param>
    /// <param name="isLive">Whether the data is live or demo (honesty line).</param>
    /// <param name="boardDeckUrl">Optional absolute URL to the full board deck; when set a
    /// "View the full board deck" link is added. Never invented - omitted if not configured.</param>
    /// <param name="orgLabel">Optional org/tenant friendly label for the subject line; when
    /// absent the subject is generic (no tenant id, no customer name in the rendered text).</param>
    public static ExecEmailMessage Render(
        ExecHeadline headline,
        ExecDashboard dashboard,
        string execSummary,
        bool summaryFromAi,
        bool isLive,
        string? boardDeckUrl = null,
        string? orgLabel = null)
    {
        var h = HtmlEncoder.Default;
        var asOf = dashboard.CurrentTime?.ToString("d MMMM yyyy", CultureInfo.InvariantCulture) ?? "the latest snapshot";
        var scoreText = headline.Score.ToString("0.#", CultureInfo.InvariantCulture);

        var subject = string.IsNullOrWhiteSpace(orgLabel)
            ? $"Security posture: {dashboard.ScoreBand} ({DirWord(dashboard.Direction)}) - as of {asOf}"
            : $"Security posture for {orgLabel}: {dashboard.ScoreBand} ({DirWord(dashboard.Direction)}) - as of {asOf}";

        var topRisks = dashboard.TopRisks.Take(3).ToList();
        var actions = dashboard.QuickWins.Take(3).ToList();

        // ---- HTML body (inline-styled, table-based for mail-client safety) ---------
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\">")
          .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head>")
          .Append("<body style=\"margin:0;padding:0;background:#eef1f5;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#1c2733;\">");
        sb.Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#eef1f5;\"><tr><td align=\"center\" style=\"padding:20px;\">");
        sb.Append("<table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:600px;width:100%;background:#ffffff;border-radius:10px;overflow:hidden;\">");

        // Header band: score + band.
        sb.Append("<tr><td style=\"padding:22px 24px;border-bottom:2px solid #1c2733;\">")
          .Append("<div style=\"font-size:20px;font-weight:700;\">Security posture - executive summary</div>")
          .Append("<div style=\"color:#5a6b7d;font-size:13px;margin-top:4px;\">As of ").Append(h.Encode(asOf))
          .Append(" &middot; ").Append(isLive ? "live data" : "demo data").Append("</div></td></tr>");

        // Headline verdict + score/band badge.
        sb.Append("<tr><td style=\"padding:18px 24px 4px;\">")
          .Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>")
          .Append("<td style=\"vertical-align:top;\"><div style=\"font-size:17px;font-weight:700;line-height:1.4;\">")
          .Append(h.Encode(headline.Sentence)).Append("</div></td>")
          .Append("<td width=\"96\" style=\"vertical-align:top;text-align:center;padding-left:14px;\">")
          .Append("<div style=\"").Append(BadgeStyle(dashboard.ScoreBand)).Append("border-radius:10px;padding:8px 6px;\">")
          .Append("<div style=\"font-size:26px;font-weight:800;line-height:1;\">").Append(h.Encode(scoreText)).Append("</div>")
          .Append("<div style=\"font-size:12px;font-weight:700;margin-top:2px;\">").Append(h.Encode(dashboard.ScoreBand)).Append("</div>")
          .Append("</div></td></tr></table></td></tr>");

        // KPI strip (period direction + new/resolved).
        sb.Append("<tr><td style=\"padding:8px 24px 0;\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>");
        KpiCell(sb, h, "Direction", DirArrow(dashboard.ScoreDelta) + " " + DirWord(dashboard.Direction));
        KpiCell(sb, h, "New", dashboard.NewCount.ToString(CultureInfo.InvariantCulture));
        KpiCell(sb, h, "Resolved", dashboard.ClosedCount.ToString(CultureInfo.InvariantCulture));
        KpiCell(sb, h, "In scope", dashboard.TotalFindings.ToString(CultureInfo.InvariantCulture));
        sb.Append("</tr></table></td></tr>");

        // What this means (the grounded narrative).
        sb.Append("<tr><td style=\"padding:18px 24px 4px;\">")
          .Append("<div style=\"font-size:14px;font-weight:700;border-bottom:1px solid #dde4ec;padding-bottom:5px;margin-bottom:8px;\">What this means</div>")
          .Append("<div style=\"font-size:14px;line-height:1.5;color:#34434f;\">").Append(ParaText(execSummary, h)).Append("</div></td></tr>");

        // Top risks.
        if (topRisks.Count > 0)
        {
            sb.Append("<tr><td style=\"padding:14px 24px 0;\">")
              .Append("<div style=\"font-size:14px;font-weight:700;border-bottom:1px solid #dde4ec;padding-bottom:5px;margin-bottom:8px;\">Top risks right now</div>");
            foreach (var r in topRisks)
            {
                var why = string.IsNullOrEmpty(r.RiskFactorConsequence) ? r.RiskFactorProbability : r.RiskFactorConsequence;
                sb.Append("<div style=\"padding:6px 0;border-bottom:1px solid #f0f3f7;\">")
                  .Append("<span style=\"font-weight:600;\">").Append(h.Encode(r.ConfigurationName)).Append("</span>")
                  .Append(string.IsNullOrEmpty(r.SecuritySeverity) ? "" :
                      " <span style=\"font-size:11px;font-weight:700;color:#b5650f;\">(" + h.Encode(r.SecuritySeverity) + ")</span>")
                  .Append("<div style=\"font-size:12px;color:#5a6b7d;margin-top:2px;\">").Append(h.Encode(why)).Append("</div></div>");
            }
            sb.Append("</td></tr>");
        }

        // Recommended next actions.
        if (actions.Count > 0)
        {
            sb.Append("<tr><td style=\"padding:14px 24px 0;\">")
              .Append("<div style=\"font-size:14px;font-weight:700;border-bottom:1px solid #dde4ec;padding-bottom:5px;margin-bottom:8px;\">Recommended next actions</div>")
              .Append("<ol style=\"margin:0;padding-left:20px;font-size:14px;line-height:1.5;\">");
            foreach (var a in actions)
            {
                sb.Append("<li style=\"padding:2px 0;\"><span style=\"font-weight:600;\">").Append(h.Encode(a.Title)).Append("</span>")
                  .Append(" <span style=\"font-size:12px;color:#b5650f;font-weight:700;\">").Append(h.Encode(a.Urgency)).Append("</span></li>");
            }
            sb.Append("</ol></td></tr>");
        }

        // Board-deck link (only when configured - never invented).
        if (!string.IsNullOrWhiteSpace(boardDeckUrl))
        {
            sb.Append("<tr><td style=\"padding:18px 24px 6px;\">")
              .Append("<a href=\"").Append(h.Encode(boardDeckUrl)).Append("\" style=\"display:inline-block;background:#4ea1ff;color:#ffffff;text-decoration:none;font-weight:700;font-size:14px;padding:10px 18px;border-radius:8px;\">View the full board deck</a>")
              .Append("</td></tr>");
        }

        // Footer: honesty line.
        sb.Append("<tr><td style=\"padding:16px 24px 22px;\">")
          .Append("<div style=\"border-top:1px solid #dde4ec;padding-top:10px;font-size:11px;color:#7a8a9b;\">")
          .Append(summaryFromAi ? "Summary written by AI, grounded in the findings." : "Summary generated from the findings (AI unavailable).")
          .Append(" Counts and risks are read directly from the latest analysis snapshot - no cost or likelihood is implied.")
          .Append("</div></td></tr>");

        sb.Append("</table></td></tr></table></body></html>");

        return new ExecEmailMessage(subject, sb.ToString(), RenderText(headline, dashboard, execSummary, summaryFromAi, isLive, asOf, scoreText, boardDeckUrl, topRisks, actions));
    }

    private static string RenderText(
        ExecHeadline headline, ExecDashboard d, string execSummary, bool summaryFromAi, bool isLive,
        string asOf, string scoreText, string? boardDeckUrl,
        IReadOnlyList<RiskRow> topRisks, IReadOnlyList<QuickWin> actions)
    {
        var sb = new StringBuilder();
        sb.Append("SECURITY POSTURE - EXECUTIVE SUMMARY\n");
        sb.Append("As of ").Append(asOf).Append(isLive ? " (live data)\n" : " (demo data)\n");
        sb.Append(new string('=', 52)).Append('\n');
        sb.Append(headline.Sentence).Append("\n\n");
        sb.Append("Score: ").Append(scoreText).Append("  Band: ").Append(d.ScoreBand)
          .Append("  Direction: ").Append(DirWord(d.Direction)).Append('\n');
        sb.Append("New: ").Append(d.NewCount).Append("   Resolved: ").Append(d.ClosedCount)
          .Append("   In scope: ").Append(d.TotalFindings).Append("\n\n");

        sb.Append("WHAT THIS MEANS\n").Append((execSummary ?? "").Trim()).Append("\n\n");

        if (topRisks.Count > 0)
        {
            sb.Append("TOP RISKS RIGHT NOW\n");
            foreach (var r in topRisks)
            {
                var why = string.IsNullOrEmpty(r.RiskFactorConsequence) ? r.RiskFactorProbability : r.RiskFactorConsequence;
                sb.Append("  - ").Append(r.ConfigurationName);
                if (!string.IsNullOrEmpty(r.SecuritySeverity)) sb.Append(" (").Append(r.SecuritySeverity).Append(')');
                sb.Append('\n');
                if (!string.IsNullOrWhiteSpace(why)) sb.Append("      ").Append(why).Append('\n');
            }
            sb.Append('\n');
        }

        if (actions.Count > 0)
        {
            sb.Append("RECOMMENDED NEXT ACTIONS\n");
            var i = 1;
            foreach (var a in actions)
            {
                sb.Append("  ").Append(i++).Append(". ").Append(a.Title).Append(" [").Append(a.Urgency).Append("]\n");
            }
            sb.Append('\n');
        }

        if (!string.IsNullOrWhiteSpace(boardDeckUrl))
        {
            sb.Append("Full board deck: ").Append(boardDeckUrl).Append("\n\n");
        }

        sb.Append(summaryFromAi ? "Summary written by AI, grounded in the findings." : "Summary generated from the findings (AI unavailable).");
        sb.Append(" Counts and risks are read directly from the latest analysis snapshot - no cost or likelihood is implied.\n");
        return sb.ToString();
    }

    private static void KpiCell(StringBuilder sb, HtmlEncoder h, string label, string value)
    {
        sb.Append("<td width=\"25%\" style=\"padding:4px;\"><div style=\"background:#f4f7fa;border:1px solid #dde4ec;border-radius:8px;padding:8px 6px;text-align:center;\">")
          .Append("<div style=\"font-size:11px;color:#5a6b7d;\">").Append(h.Encode(label)).Append("</div>")
          .Append("<div style=\"font-size:15px;font-weight:700;margin-top:2px;\">").Append(h.Encode(value)).Append("</div></div></td>");
    }

    private static string ParaText(string text, HtmlEncoder h)
    {
        var paras = (text ?? "").Replace("\r", "").Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
        if (paras.Length == 0) return "<p style=\"margin:0;\">" + h.Encode(text ?? "") + "</p>";
        return string.Concat(paras.Select(p => "<p style=\"margin:0 0 8px;\">" + h.Encode(p.Trim()).Replace("\n", "<br>") + "</p>"));
    }

    private static string BadgeStyle(string band) => band.ToLowerInvariant() switch
    {
        "low" => "background:#e3f7ee;color:#1a7a4f;",
        "moderate" => "background:#fff6da;color:#9a7400;",
        "elevated" => "background:#fff0df;color:#b5650f;",
        "severe" => "background:#fde4e4;color:#b51f1f;",
        _ => "background:#f4f7fa;color:#1c2733;",
    };

    private static string DirArrow(double delta) => delta < 0 ? "v" : delta > 0 ? "^" : "-";
    private static string DirWord(string dir) => dir switch { "improving" => "improving", "worsening" => "worsening", _ => "steady" };
}
