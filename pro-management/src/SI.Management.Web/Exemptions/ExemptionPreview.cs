using SI.Management.Web.Changes;

namespace SI.Management.Web.Exemptions;

/// <summary>
/// #330: what the "Request exemption" dialog shows for ONE selection before anything is written -- who approves it (the
/// resolved names of the most specific owners per request), whether the requester may approve it all at once (only
/// then is "Approve now" offered), whom else the requester could ask instead (only people who decide EVERY part; no
/// choice = no "Change approver"), and the one wider scope that makes sense for the selection. PURE over the roster.
/// </summary>
public sealed record ExemptionPreview(IReadOnlyList<ExemptionPreview.Part> Parts, bool CanApproveAll, IReadOnlyList<string> Overrides,
    IReadOnlyList<ExemptionPreview.Alternative> Alternatives, int AlreadyExempted)
{
    /// #391: the department whose own page the selection was made on (null elsewhere), and whether its business approvers
    /// are the ones asked (false = it has none, so the security owners are -- the dialog says so).
    public string? Department { get; init; }
    public bool ToDepartment { get; init; }

    /// One request-to-be: its domain / category label and the people asked to approve it (empty = no owner yet).
    public sealed record Part(string Label, IReadOnlyList<string> Approvers);

    /// A wider scope than the selection: its value (a.scope) and the sentence the dialog shows.
    public sealed record Alternative(string Scope, string Label);

    /// The most names one part lists before "and N more".
    public const int NamesShown = 4;

    /// "Approved by alice@contoso.test and bob@contoso.test." -- or, per part, "Endpoint: ...; Identity: ...".
    public string ApproversText
    {
        get
        {
            if (Parts.Count == 0) return "";
            static string Names(IReadOnlyList<string> n) => n.Count == 0 ? "no owner yet -- an Admin decides"
                : n.Count <= NamesShown ? Join(n) : string.Join(", ", n.Take(NamesShown - 1)) + $" and {n.Count - (NamesShown - 1)} more";
            static string Join(IReadOnlyList<string> n) => n.Count == 1 ? n[0] : string.Join(", ", n.Take(n.Count - 1)) + " or " + n[^1];
            // #391: on a department's own page its business approvers approve every part (one sentence); without any, the
            // owners do and the sentence says why
            if (ToDepartment) return $"Approved by {Names(Parts[0].Approvers)} (business approvers of {Department}).";
            var lead = Department is null ? "" : $"{Department} has no business approver, so the security owners approve it. ";
            if (Parts.Count == 1) return lead + (Parts[0].Approvers.Count == 0 ? $"{Parts[0].Label} has no owner yet -- an Admin decides." : $"Approved by {Names(Parts[0].Approvers)} ({Parts[0].Label}).");
            return lead + "Approved by " + string.Join("; ", Parts.Select(p => $"{p.Label}: {Names(p.Approvers)}")) + ".";
        }
    }

    /// The issue of a finding as an exemption keys it (a CVE, else a configuration id).
    private static string? IssueKey(FindingRef f) => !string.IsNullOrWhiteSpace(f.Cve) ? f.Cve.Trim() : string.IsNullOrWhiteSpace(f.ConfigurationId) ? null : f.ConfigurationId.Trim();

    /// <summary>
    /// The scopes a selection may be requested with: always "finding" (exactly the selection); "issue" (that issue on
    /// every asset, now and later) only when the whole selection is ONE issue; "asset" (every finding on that asset, now
    /// and later) only when it is ONE asset with several issues. Never both, never for a mixed selection -- so "every
    /// finding on each asset" never appears for a CVE.
    /// </summary>
    public static IReadOnlyList<Alternative> AlternativesOf(IReadOnlyCollection<FindingRef> findings)
    {
        if (findings.Count == 0) return Array.Empty<Alternative>();
        var issues = findings.Select(IssueKey).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (issues.Count == 1 && issues[0] is { } issue)
            return [new(ExemptionRepository.ScopeIssue, $"Also future assets: exempt {issue} on every asset, now and later")];
        var assets = findings.Select(f => f.AssetKey).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (assets.Count == 1 && assets[0].Length > 0)
        {
            var name = findings.Select(f => f.AssetName).FirstOrDefault(n => !string.IsNullOrWhiteSpace(n)) ?? assets[0];
            return [new(ExemptionRepository.ScopeAsset, $"Also future findings: exempt every finding on {name}, now and later")];
        }
        return Array.Empty<Alternative>();
    }

    /// Whether a scope may be requested for these findings (the server's check of what the dialog offered).
    public static bool Allows(string scope, IReadOnlyCollection<FindingRef> findings) =>
        scope == ExemptionRepository.ScopeFinding || AlternativesOf(findings).Any(a => a.Scope == scope);

    /// <summary>
    /// The preview of a selection; <paramref name="canDecide"/> = may the requester decide (domain, category). #391:
    /// <paramref name="department"/> = the department whose own page it was made on: with business approvers, THEY are
    /// named for every part, "Approve now" is offered to one of them (<paramref name="userIsBusinessApprover"/>), and
    /// "Change approver" lists them plus the security owners who decide every part; without any, the owners as elsewhere
    /// and the sentence says so.
    /// </summary>
    public static ExemptionPreview Build(Roster roster, IReadOnlyCollection<FindingRef> findings, Func<string, string?, bool> canDecide, int alreadyExempted = 0,
        DepartmentApproverSet? department = null, bool userIsBusinessApprover = false)
    {
        var groups = ExemptionWorkflow.Groups(roster, findings);
        var toDept = department is { Any: true } && groups.Count > 0;
        var parts = groups.Select(g => new Part(g.Label, toDept ? department!.Names : g.Asked)).ToList();
        var can = groups.Count > 0 && (groups.All(g => canDecide(g.Domain, g.Category)) || (toDept && userIsBusinessApprover));
        // another approver: only someone who decides EVERY part (a request is refused for a part its approver does not
        // decide). A real choice only: someone not already asked, or one of several asked -- never a list of one that just
        // repeats the default.
        var asked = (toDept ? department!.Names : groups.SelectMany(g => g.Asked)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        IEnumerable<string>? common = null;
        foreach (var g in groups) common = common is null ? g.Deciders : common.Intersect(g.Deciders, StringComparer.OrdinalIgnoreCase);
        // #391: on a department's page the business approvers (those with a mail address -- the request is mailed to the
        // one picked) decide every part too
        if (toDept) common = department!.Mails.Concat(common ?? Array.Empty<string>()).Distinct(StringComparer.OrdinalIgnoreCase);
        var choice = (common ?? Array.Empty<string>()).OrderBy(p => p, StringComparer.Ordinal).ToList();
        var overrides = choice.Any(p => !asked.Contains(p)) || choice.Count > 1 ? choice : new List<string>();
        return new ExemptionPreview(parts, can, overrides, AlternativesOf(findings), alreadyExempted)
        {
            Department = department?.Name, ToDepartment = toDept,
        };
    }
}
