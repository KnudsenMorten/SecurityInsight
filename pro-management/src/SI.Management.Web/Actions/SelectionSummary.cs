using SI.Management.Core.ProData;

using Fmt = SI.Management.Web.Pages.Fmt;

namespace SI.Management.Web.Actions;

/// <summary>
/// #330: WHAT a selection is, in the words the action dialog opens with -- "CVE-2026-33824 on 3 assets", "1 finding:
/// CVE-2026-33824 on dc1", "12 selected findings". Built from the findings the server read back (the same resolver Apply
/// uses), so the dialog names exactly what the action will act on. PURE.
/// </summary>
public sealed record SelectionSummary(int Findings, int Assets, int Issues, string? Issue, string? Asset, long? Rows, string? RowNoun)
{
    /// The issue a finding is about: its CVE, else its configuration id, else its title.
    public static string? IssueOf(FindingRow f) =>
        !string.IsNullOrWhiteSpace(f.Cve) ? f.Cve.Trim() : !string.IsNullOrWhiteSpace(f.ConfigurationId) ? f.ConfigurationId.Trim() : string.IsNullOrWhiteSpace(f.Title) ? null : f.Title.Trim();

    /// The asset as people read it: its name, else its key.
    public static string AssetOf(FindingRow f) => !string.IsNullOrWhiteSpace(f.AssetName) ? f.AssetName.Trim() : f.AssetKey;

    public static SelectionSummary Of(IReadOnlyCollection<FindingRow> findings, long? rows = null, string? rowNoun = null)
    {
        var assets = findings.Select(f => f.AssetKey.Length > 0 ? f.AssetKey : AssetOf(f)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var issues = findings.Select(IssueOf).Where(i => i is not null).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var oneIssue = issues.Count == 1 && findings.All(f => IssueOf(f) is not null) ? issues[0] : null;
        var oneAsset = assets == 1 && findings.Count > 0 ? AssetOf(findings.First()) : null;
        return new SelectionSummary(findings.Count, assets, issues.Count, oneIssue, oneAsset, rows, rowNoun);
    }

    private static string N(long n, string one, string many) => Fmt.Int(n) + " " + (n == 1 ? one : many);

    /// The selection in one phrase (no verb): what the dialog's title and the no-script page say.
    public string What
    {
        get
        {
            if (Findings == 0) return "no finding";
            if (Findings == 1) return Issue is not null && Asset is not null ? $"1 finding: {Issue} on {Asset}" : "1 selected finding";
            if (Issue is not null)
                return Assets == 1 ? $"{Issue} on {Asset} ({N(Findings, "finding", "findings")})"
                    : Assets == Findings ? $"{Issue} on {N(Assets, "asset", "assets")}"
                    : $"{Issue} on {N(Assets, "asset", "assets")} ({N(Findings, "finding", "findings")})";
            if (Asset is not null) return $"{N(Findings, "finding", "findings")} on {Asset}";
            if (Rows is { } r && string.Equals(RowNoun, "CVE", StringComparison.Ordinal))
                return $"{N(r, "CVE", "CVEs")} on {N(Assets, "asset", "assets")} ({N(Findings, "finding", "findings")})";
            if (Rows is { } r2 && RowNoun is { } noun && noun != "finding")
                return $"{N(Findings, "finding", "findings")} from {N(r2, noun + " row", noun + " rows")}";
            return $"{N(Findings, "selected finding", "selected findings")}";
        }
    }
}
