using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One control-area score in a board-reporting framework (CIS / NIST CSF / ISO 27001).
/// <see cref="Score"/> is the summed RA risk that maps into this control area for the
/// latest snapshot (grounded - a partition of the real findings, never invented);
/// <see cref="Findings"/> is how many findings landed here; <see cref="Plain"/> is a
/// non-technical one-liner an exec already reports against at board level.
/// </summary>
public sealed record ControlAreaScore(string Area, double Score, int Findings, string Plain);

/// <summary>A named board framework with its rolled-up control-area scores (highest risk first).</summary>
public sealed record FrameworkView(string Framework, IReadOnlyList<ControlAreaScore> Areas);

/// <summary>
/// Framework lens (REQUIREMENTS.md "SI Analyzer" - "Framework lens (CIS / NIST CSF / ISO 27001)"):
/// rolls the posture up to the few control-area scores execs already report to the board in.
///
/// This is a HIGH-LEVEL mapping, not per-control noise: every latest-snapshot RA finding is
/// attributed to exactly ONE control area per framework, using the finding's own
/// <see cref="RiskRow.SecurityDomain"/> plus keyword signals in its plain-language
/// <see cref="RiskRow.RiskFactorProbability"/>/<see cref="RiskRow.RiskFactorConsequence"/>
/// driver text. The control-area score is the SUM of the mapped findings' RiskScoreTotal -
/// a pure partition of the grounded headline number (the area scores sum back to the
/// headline), so the AI narrates it but never invents a control score.
/// </summary>
public static class FrameworkLens
{
    /// <summary>Build all three board frameworks from the latest snapshot rows.</summary>
    public static IReadOnlyList<FrameworkView> Build(IReadOnlyList<RiskRow> latest) => new[]
    {
        BuildOne("NIST CSF", latest, NistArea),
        BuildOne("CIS Controls", latest, CisArea),
        BuildOne("ISO 27001", latest, IsoArea),
    };

    private static FrameworkView BuildOne(
        string framework,
        IReadOnlyList<RiskRow> latest,
        Func<RiskRow, string> map)
    {
        var areas = latest
            .GroupBy(map)
            .Select(g => new ControlAreaScore(
                g.Key,
                Math.Round(g.Sum(r => r.RiskScoreTotal), 1),
                g.Count(),
                AreaPlain(g.Key)))
            .OrderByDescending(a => a.Score)
            .ToList();
        return new FrameworkView(framework, areas);
    }

    // --- Mapping helpers (grounded: drive off the finding's own domain + driver text) ---

    private static bool Has(RiskRow r, params string[] needles)
    {
        var hay = r.RiskFactorProbability + " " + r.RiskFactorConsequence;
        foreach (var n in needles)
        {
            if (hay.Contains(n, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>NIST CSF functions: Identify / Protect / Detect. High-level only.</summary>
    private static string NistArea(RiskRow r)
    {
        // Visibility/onboarding gaps are a DETECT shortfall (we cannot see the asset).
        if (Has(r, "onboarding", "not managed", "not fully managed", "sensor", "no owner"))
            return "Detect (visibility)";
        // Exposure / exploitable surface is a PROTECT shortfall.
        if (Has(r, "internet", "exposed", "public", "open", "port", "cve", "vuln", "unpatched", "eol", "unsupported"))
            return "Protect (exposure)";
        // Identity/privilege weaknesses are an IDENTIFY (asset/identity governance) shortfall.
        if (r.SecurityDomain.Contains("identity", StringComparison.OrdinalIgnoreCase)
            || Has(r, "mfa", "privileged", "admin", "stale", "rotat", "lateral"))
            return "Identify (identity & access)";
        return "Protect (configuration)";
    }

    /// <summary>CIS Controls IG1 themes (a small board-level subset).</summary>
    private static string CisArea(RiskRow r)
    {
        if (Has(r, "mfa", "privileged", "admin", "lateral", "stale", "rotat", "no owner"))
            return "Account & Access Management";
        if (Has(r, "cve", "vuln", "unpatched", "eol", "unsupported"))
            return "Vulnerability Management";
        if (Has(r, "onboarding", "not managed", "not fully managed", "sensor"))
            return "Asset Inventory & Monitoring";
        if (Has(r, "internet", "exposed", "public", "open", "port"))
            return "Network & Boundary Defense";
        return "Secure Configuration";
    }

    /// <summary>ISO 27001 Annex A clause groupings (high level).</summary>
    private static string IsoArea(RiskRow r)
    {
        if (Has(r, "mfa", "privileged", "admin", "stale", "rotat", "lateral", "no owner"))
            return "A.5 Access control & identity";
        if (Has(r, "cve", "vuln", "unpatched", "eol", "unsupported"))
            return "A.8 Technical vulnerability mgmt";
        if (Has(r, "internet", "exposed", "public", "open", "port"))
            return "A.8 Network security";
        if (Has(r, "onboarding", "not managed", "not fully managed", "sensor"))
            return "A.8 Logging & monitoring";
        return "A.8 Secure configuration";
    }

    private static string AreaPlain(string area) => area switch
    {
        "Detect (visibility)" => "Assets we cannot fully see or monitor yet.",
        "Protect (exposure)" => "Exposed or exploitable surface that needs hardening.",
        "Identify (identity & access)" => "Who can access what, and how well it is governed.",
        "Protect (configuration)" => "Configuration weaknesses to remediate.",
        "Account & Access Management" => "Privileged, stale or unowned accounts.",
        "Vulnerability Management" => "Unpatched, EOL or vulnerable software.",
        "Asset Inventory & Monitoring" => "Onboarding and coverage gaps.",
        "Network & Boundary Defense" => "Internet-facing and open-port exposure.",
        "Secure Configuration" => "Hardening and configuration baselines.",
        "A.5 Access control & identity" => "Access control and identity governance.",
        "A.8 Technical vulnerability mgmt" => "Patching and vulnerability remediation.",
        "A.8 Network security" => "Network exposure and segmentation.",
        "A.8 Logging & monitoring" => "Coverage, logging and monitoring gaps.",
        "A.8 Secure configuration" => "Secure configuration of assets.",
        _ => "Control area derived from the findings in scope.",
    };
}
