using System.Text;
using System.Text.Json;
using Sia.Core.Model;

namespace Sia.Core.Ai;

/// <summary>The audience a narrative is written for.</summary>
public enum Audience
{
    /// <summary>Non-technical leader. No jargon, no table names, no KQL.</summary>
    Management,
    /// <summary>Security analyst. Concrete + actionable, technical OK.</summary>
    Analyst,
}

/// <summary>
/// Grounded AI prompt assembly + the AI-optional templated fallback - the pure C#
/// port of analyzer/lib/SiAnalyzer-Ai.ps1 (the parts that are pure string logic;
/// the actual Azure OpenAI HTTP call lives in the Web project's AI service so this
/// core stays SDK-free and fully unit-testable).
///
/// GROUNDING CONTRACT (enforced in the prompt text): the model is ALWAYS handed the
/// actual KQL result rows and instructed to use ONLY those rows, to trace every claim
/// to a row, and to never invent assets/scores/facts. AI is fail-soft: callers fall
/// back to <see cref="TemplatedSummary"/> when AI is unavailable.
/// </summary>
public static class GroundedPrompt
{
    private static readonly JsonSerializerOptions RowJson = new() { WriteIndented = true };

    /// <summary>Compact the rows to a JSON block to ground the model (caps the rows
    /// passed - the worklist top-N - never the data scanned for the rollup).</summary>
    public static string RowsForGrounding(IReadOnlyList<RiskRow> rows, int maxRows = 50)
    {
        var take = rows.Take(maxRows).ToList();
        return JsonSerializer.Serialize(take, RowJson);
    }

    /// <summary>
    /// Build the grounded verdict/summary prompt. Mirrors Build-SiGroundedPrompt:
    /// the instruction + the grounding rules + the audience tone + the data rows.
    /// </summary>
    public static string BuildGrounded(string instruction, IReadOnlyList<RiskRow> rows, Audience audience = Audience.Analyst, int maxRows = 50)
    {
        var rowsJson = RowsForGrounding(rows, maxRows);
        var rowCount = rows.Count;
        var tone = audience == Audience.Management
            ? "Write for a non-technical leader. No jargon, no table names, no KQL. Lead with what it means for the business and what to do."
            : "Write for a security analyst. Be concrete and actionable. For each finding give: what it is, why it matters, what to do, how urgent.";

        return
            $"{instruction}\n\n" +
            "GROUNDING RULES (must follow):\n" +
            "- Use ONLY the data rows below. Do not invent assets, scores, or facts.\n" +
            "- Every claim must trace to a row. If the data does not support a claim, say so.\n" +
            $"- {tone}\n\n" +
            $"There are {rowCount} finding rows in scope (showing up to {maxRows} below):\n\n" +
            "DATA ROWS (JSON):\n" +
            rowsJson;
    }

    /// <summary>
    /// Build the NL-&gt;KQL composition prompt. Mirrors Build-SiNlToKqlPrompt: gives the
    /// model the schema, the allow-list, and a hard read-only contract. The output is
    /// STILL re-checked by the guardrail before execution - this is a first line, not
    /// the only line, of defence.
    /// </summary>
    public static string BuildNlToKql(string question, IReadOnlyList<string> allowedTables)
    {
        var tableList = string.Join(", ", allowedTables);
        return
            "You translate a plain-English security question into a SINGLE read-only Kusto (KQL) query\n" +
            "over a Microsoft Sentinel / Log Analytics workspace.\n\n" +
            "HARD RULES:\n" +
            "- READ-ONLY ONLY. Never emit a control command (anything starting with '.'), never use\n" +
            "  set/append/create/drop/alter/delete/ingest/purge/externaldata/cluster()/database().\n" +
            $"- Read ONLY from these tables: {tableList}\n" +
            "- The SCORED findings are in SI_RiskAnalysis_Summary_CL (prefer this for risk questions).\n" +
            "  Its columns: SecurityDomain (Endpoint/Identity/Azure/PublicIP/CrossEngine), Category, Subcategory,\n" +
            "  ConfigurationName, ConfigurationId, CriticalityTier (int 0-3), CriticalityTierLevel (text),\n" +
            "  SecuritySeverity (Critical/High/Medium/Low), RiskScoreTotal, RiskScoreTotal_Weighted,\n" +
            "  RiskFactor_Consequence_Detailed and RiskFactor_Probability_Detailed (PLAIN-LANGUAGE driver text -\n" +
            "  match keywords against THESE), CollectionTime.\n" +
            "  NOTE: RiskFactor_Consequence / RiskFactor_Probability (no _Detailed) are NUMERIC factors, not text -\n" +
            "  do NOT keyword-match them; use the _Detailed columns for any has/contains filter.\n" +
            "- The SI_*_Profile_CL tables hold asset ATTRIBUTES only (Tier, DisplayName, Hostname/Upn, ...) and do\n" +
            "  NOT carry RiskScoreTotal - use them only for attribute lookups, not for scoring.\n" +
            "- Anchor on the latest snapshot: filter `where CollectionTime == toscalar(<Table> | summarize max(CollectionTime))`.\n" +
            "- End with a reasonable `take` (<= 200). Return ONLY the KQL, no prose, no markdown fences.\n\n" +
            "QUESTION:\n" +
            question;
    }

    /// <summary>
    /// AI-optional fallback: a plain-language summary from the rows with NO AI.
    /// Mirrors Get-SiTemplatedSummary - warn, never hard-fail. This is what the exec
    /// summary / analyst verdict degrade to when OpenAI is unreachable.
    /// </summary>
    public static string TemplatedSummary(IReadOnlyList<RiskRow> rows, Audience audience = Audience.Analyst, DiffSummary? diff = null)
    {
        if (rows.Count == 0)
        {
            return "No findings in the current snapshot. (AI summary unavailable -- showing a generated summary.)";
        }

        var total = rows.Sum(r => r.RiskScoreTotal);
        var top = rows.OrderByDescending(r => r.RiskScoreTotal).Take(5).ToList();

        var sb = new StringBuilder();
        if (audience == Audience.Management)
        {
            sb.AppendLine("Overall risk picture (auto-generated -- AI summary unavailable):");
            sb.AppendLine($"- {rows.Count} findings in scope, combined risk score {Math.Round(total, 1)}.");
            if (diff is not null)
            {
                var dir = diff.ScoreDelta < 0 ? "down" : diff.ScoreDelta > 0 ? "up" : "unchanged";
                sb.AppendLine($"- Risk is {dir} {Math.Abs(diff.ScoreDelta)} since the previous snapshot ({diff.NewCount} new, {diff.ClosedCount} closed).");
            }
            sb.AppendLine("- Biggest contributors to risk right now:");
            foreach (var r in top)
            {
                sb.AppendLine($"    * {r.ConfigurationName} ({r.CriticalityTierLevel}) -- score {Math.Round(r.RiskScoreTotal, 1)}");
            }
            sb.AppendLine("Recommendation: focus remediation on the highest-scoring critical-tier items above for the biggest score reduction.");
        }
        else
        {
            sb.AppendLine("Top findings (auto-generated -- AI verdict unavailable):");
            foreach (var r in top)
            {
                var sev = string.IsNullOrEmpty(r.SecuritySeverity) ? "n/a" : r.SecuritySeverity;
                sb.AppendLine($"- {r.ConfigurationName} [{r.CriticalityTierLevel}, severity {sev}, score {Math.Round(r.RiskScoreTotal, 1)}]");
                if (!string.IsNullOrEmpty(r.RiskFactorConsequence))
                {
                    sb.AppendLine($"    why: {r.RiskFactorConsequence}");
                }
            }
            sb.AppendLine("Action: triage highest score first; verify the contributing factors above in the evidence rows.");
        }
        return sb.ToString().TrimEnd();
    }
}

/// <summary>Minimal diff facts the templated summary needs (decouples Core.Ai from Core.Analysis).</summary>
public sealed record DiffSummary(double ScoreDelta, int NewCount, int ClosedCount);
