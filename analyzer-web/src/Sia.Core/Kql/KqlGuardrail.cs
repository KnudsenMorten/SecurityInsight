using System.Text.RegularExpressions;

namespace Sia.Core.Kql;

/// <summary>Result of the read-only KQL guardrail check.</summary>
public sealed record GuardrailResult(bool Allowed, IReadOnlyList<string> Reasons, IReadOnlyList<string> Tables);

/// <summary>
/// The read-only KQL guardrail - a faithful C# port of the proven PowerShell
/// <c>Test-SiKqlReadOnly</c> (analyzer/lib/SiAnalyzer-Kql.ps1). This is the SINGLE
/// gate every prestaged AND AI-generated query must pass before it is submitted to
/// Log Analytics. It rejects:
///   * control commands (any statement starting with '.'),
///   * destructive / mutating / external-reach operators,
///   * cross-cluster / cross-database reach (cluster()/database()),
///   * any table outside the canonical SI allow-list,
///   * ungrounded / empty queries.
/// Keeps the engine's read-only invariant intact even for AI-composed KQL.
/// </summary>
public static class KqlGuardrail
{
    /// <summary>
    /// The canonical SI table allow-list - the ONLY tables a generated or prestaged
    /// query may read (RA Profile tables + ExposureGraph + the read-only Defender/Graph
    /// hunting tables the engine already consumes). Matches the PS allow-list 1:1.
    /// </summary>
    public static readonly IReadOnlyList<string> AllowedTables = new[]
    {
        // RA output tables - the SCORED findings (RiskScoreTotal, SecuritySeverity,
        // CriticalityTierLevel, RiskFactor_*). This is where the exec rollup + worklist
        // source their numbers; the Profile_CL tables below carry asset ATTRIBUTES only
        // (Tier, DisplayName, Hostname/Upn, ...) and do NOT contain RiskScoreTotal.
        SiTables.RiskAnalysisSummary,   // SI_RiskAnalysis_Summary_CL
        SiTables.RiskAnalysisDetailed,  // SI_RiskAnalysis_Detailed_CL
        // Asset-profile attribute tables (one flat row per asset, per snapshot).
        SiTables.EndpointProfile,
        SiTables.IdentityProfile,
        SiTables.AzureProfile,
        SiTables.PublicIpProfile,
        "SI_VulnerabilityPIP_CL",
        // Read-only Defender/Graph hunting tables the engine already consumes.
        "ExposureGraphNodes",
        "ExposureGraphEdges",
        "DeviceInfo",
        "DeviceTvmSoftwareVulnerabilities",
        "IdentityInfo",
    };

    // Destructive / mutating / external-reach operators (case-insensitive). These
    // never appear in a legitimate read-only SI analytics query. Ported verbatim
    // from the PS $bannedOperators list.
    private static readonly string[] BannedOperators =
    {
        "set-or-replace", "set-or-append", "create-or-alter",
        @"\.set\b", @"\.append\b", @"\.create\b", @"\.drop\b", @"\.alter\b", @"\.delete\b",
        @"\.ingest\b", @"\.purge\b", @"\.rename\b", @"\.move\b", @"\.replace\b",
        @"\bexternaldata\b", @"\bexternal_table\b", @"\bevaluate\s+http_request\b",
        @"\bevaluate\s+http_request_post\b", @"\binto\s+table\b",
    };

    private static readonly Regex CandidateTablePattern = new(
        @"\b([A-Za-z_][A-Za-z0-9_]*_CL|ExposureGraph[A-Za-z]+|DeviceInfo|DeviceTvmSoftwareVulnerabilities|IdentityInfo)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CustomTablePattern = new(
        @"\b([A-Za-z_][A-Za-z0-9_]*_CL)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Check a query. Returns Allowed=false with reasons on any violation.</summary>
    public static GuardrailResult Check(string? query)
    {
        var reasons = new List<string>();
        var q = query ?? "";

        if (string.IsNullOrWhiteSpace(q))
        {
            return new GuardrailResult(false, new[] { "Query is empty." }, Array.Empty<string>());
        }

        // 1. Control commands - any statement beginning with '.' (.set/.create/.drop/...).
        foreach (var rawLine in q.Split('\n'))
        {
            var line = rawLine.Trim().TrimEnd('\r').Trim();
            if (line.StartsWith('.'))
            {
                reasons.Add($"Control command not allowed: '{line}'");
            }
        }

        // 2. Destructive / mutating / external operators.
        foreach (var op in BannedOperators)
        {
            var m = Regex.Match(q, op, RegexOptions.IgnoreCase);
            if (m.Success)
            {
                reasons.Add($"Disallowed operator: '{m.Value.Trim()}'");
            }
        }

        // 3. Cross-cluster / cross-database reach.
        if (Regex.IsMatch(q, @"\bcluster\s*\(", RegexOptions.IgnoreCase))
        {
            reasons.Add("Cross-cluster reference not allowed: cluster(...)");
        }
        if (Regex.IsMatch(q, @"\bdatabase\s*\(", RegexOptions.IgnoreCase))
        {
            reasons.Add("Cross-database reference not allowed: database(...)");
        }

        // 4. Table allow-list. Collect every referenced table identifier.
        var referenced = new List<string>();
        foreach (Match m in CandidateTablePattern.Matches(q))
        {
            var name = m.Groups[1].Value;
            if (!referenced.Contains(name)) referenced.Add(name);
        }
        foreach (Match m in CustomTablePattern.Matches(q))
        {
            var name = m.Groups[1].Value;
            if (!referenced.Contains(name)) referenced.Add(name);
        }

        var offList = referenced
            .Where(name => !AllowedTables.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        if (offList.Count > 0)
        {
            reasons.Add($"Table(s) not on the read-only allow-list: {string.Join(", ", offList)}");
        }

        if (referenced.Count == 0)
        {
            reasons.Add("No recognised SI/Defender table referenced -- query rejected as ungrounded.");
        }

        return new GuardrailResult(reasons.Count == 0, reasons, referenced);
    }
}
