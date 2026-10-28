using System.Security.Claims;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Departments;
using SI.Management.Web.Settings;

using Fmt = SI.Management.Web.Pages.Fmt;

namespace SI.Management.Web.Actions;

/// <summary>
/// #693 LINK AS ONE: two or more selected findings of ONE CI are one finding -- the finding that stays keeps its key, the
/// others become its evidence. Written as one recommendation-equivalence link item (<see cref="FindingLinks"/>: the same
/// store and mechanism as the shipped rules), with the reason, who and when in the item and in the change log. Effective
/// from the next Risk Analysis run: the findings count once, the outputs send it once (one ServiceNow item), the lifecycle
/// carries the members' history over, the close-loop closes a member's record as Linked (never as fixed).
/// WHO: an Admin (the role framework's Administer) -- a link changes what every view counts and what the connectors
/// send for everyone, like assigning findings to a department or changing the data model.
/// </summary>
public sealed class LinkFindingsAction(FindingLinks links, IAccessScope access) : IFindingAction, IFindingActionPreview
{
    public const string ActionKey = "link";
    public string Key => ActionKey;
    public string Label => "Link as one";
    public string? Icon => "link";
    public string Group => ActionGroups.Decide;
    public int Order => 30;
    public string Hint => "The selected findings of one CI are one finding: the one you keep stays, the others become its evidence. From the next Risk Analysis run they count once and go to the connectors once. Undo it on the finding's page.";
    public string Title(string what) => "Link " + what + " as one";
    public string AuditAction => "finding.link.create";
    public bool SupportsAllMatching => false;
    public int BulkLimit => FindingLinks.MaxMembers;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Link.cshtml";

    public Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct) => Task.FromResult(access.Can(user, AccessAction.Administer).Allowed);

    public Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct)
    {
        var d = access.Can(user, AccessAction.Administer);
        return Task.FromResult(d.Allowed ? AccessDecision.Yes : AccessDecision.No("linking findings into one is an Admin change: " + d.Reason));
    }

    /// The selection as link candidates (the owner each finding is keyed on, read from the database); null = the database
    /// does not record it yet. Findings of several collections are refused by the caller.
    public async Task<IReadOnlyList<LinkCandidate>?> CandidatesAsync(IReadOnlyList<GovernanceTarget> findings, CancellationToken ct)
    {
        var col = findings.Select(t => t.CollectionId).FirstOrDefault() ?? "";
        var owners = await links.OwnersAsync(col, findings.Select(t => t.Finding.FindingId), ct);
        if (owners is null) return null;
        return findings.Select(t => new LinkCandidate(t.Finding.FindingId, FindingLinks.KeyOf(t.Finding.ConfigurationId, t.Finding.Cve),
            owners.TryGetValue(t.Finding.FindingId, out var o) ? o : null, t.Finding.Title, t.Finding.AssetName, t.Finding.ReportName, t.Finding.Severity, t.Finding.RiskScore)).ToList();
    }

    /// PURE. Why a selection of several collections cannot be linked (null = one collection).
    public static string? Collections(IReadOnlyList<GovernanceTarget> findings) =>
        findings.Select(t => t.CollectionId).Distinct(StringComparer.Ordinal).Count() > 1 ? "the findings are of different collections -- select them in one collection" : null;

    async Task<object?> IFindingActionPreview.PreviewAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, int? department, CancellationToken ct)
    {
        var problem = Collections(findings);
        IReadOnlyList<LinkCandidate> cands = Array.Empty<LinkCandidate>();
        if (problem is null)
        {
            var c = await CandidatesAsync(findings, ct);
            if (c is null) problem = FindingLinks.MissingKeyMessage;
            else
            {
                cands = c;
                var (link, why) = FindingLinks.Build(c, null, "preview", "preview", await links.ListAsync(ct), DateTime.UtcNow);
                if (link is null) problem = string.Join("; ", why);
                else return new { linkFindings = Choices(c), linkDefault = c.First(x => string.Equals(x.Key, link.CanonicalId, StringComparison.OrdinalIgnoreCase)).FindingId, linkProblem = (string?)null };
            }
        }
        return new { linkFindings = Choices(cands), linkDefault = (string?)null, linkProblem = problem };
    }

    /// The findings offered as "the one that stays" (one per key).
    public static IEnumerable<object> Choices(IEnumerable<LinkCandidate> c) =>
        c.Where(x => x.Key is not null).GroupBy(x => x.Key!, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
         .Select(x => new { id = x.FindingId, label = x.Key + " -- " + x.Title + (x.ReportName.Length > 0 ? " (" + x.ReportName + ")" : "") + " · " + x.Severity });

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        if (Collections(findings) is { } many) return ActionOutcome.All(findings, false, many);
        var cands = await CandidatesAsync(findings, ct);
        if (cands is null) return ActionOutcome.All(findings, false, FindingLinks.MissingKeyMessage);
        var by = user.ChangeName();
        var (link, why) = FindingLinks.Build(cands, form.Get("canonical"), form.Get("reason") ?? "", by, await links.ListAsync(ct), DateTime.UtcNow);
        if (link is null) return ActionOutcome.All(findings, false, "Nothing was linked: " + string.Join("; ", why));
        var r = await links.SaveAsync(link, by, ct);
        if (r.Status != WriteStatus.Saved) return ActionOutcome.All(findings, false, "Nothing was linked: " + r.Message);
        var stays = cands.First(c => string.Equals(c.Key, link.CanonicalId, StringComparison.OrdinalIgnoreCase));
        return new ActionOutcome(findings.Select(t => FindingActionResult.Ok(t, t.Finding.FindingId == stays.FindingId || string.Equals(FindingLinks.KeyOf(t.Finding.ConfigurationId, t.Finding.Cve), link.CanonicalId, StringComparison.OrdinalIgnoreCase) ? "stays (the finding they are one of)" : "linked into " + link.CanonicalId)).ToList(),
            $"Linked {Fmt.Int(link.Members.Count)} findings on {stays.AssetName} into {link.CanonicalId} ({link.Id}). From the next Risk Analysis run they are one finding; undo it on the finding's page.");
    }
}
