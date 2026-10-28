using System.Security.Claims;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Auth;

/// <summary>
/// What a staged change touches, for <see cref="IAccessScope"/>: the action and the scope target(s). Exemptions carry
/// their target in the staged data (the page that staged them knew the finding: its domain, asset kind and tier); the
/// tier changes derive it from the asset kind / rule key they already carry. The staged data lives server-side, never in
/// the browser, so it is trusted -- and it is re-checked against the user's CURRENT access on review and on commit.
/// </summary>
public static class ChangeAccess
{
    public const string DomainKey = "access.domain";
    public const string KindKey = "access.kind";
    public const string TierKey = "access.tier";
    public const string Unclassified = "Unclassified";

    private static string? B(string? s) => SecurityDomains.Blank(s);
    private static string TierOf(string? t) => B(t) ?? Unclassified;

    /// A finding exemption: the finding's domain, asset kind and tier. An ISSUE exemption covers every asset (no kind, no
    /// tier); an ASSET exemption covers every issue of the asset, so its domain is the asset's (by its kind).
    public static ScopeTarget ForFinding(FindingRow f, string exemptionScope) => exemptionScope switch
    {
        ExemptionRepository.ScopeIssue => new(B(f.SecurityDomain) ?? SecurityDomains.OfAssetKind(f.AssetKind), null, null),
        ExemptionRepository.ScopeAsset => new(SecurityDomains.OfAssetKind(f.AssetKind), B(f.AssetKind)?.ToLowerInvariant(), TierOf(f.Tier)),
        _ => new(B(f.SecurityDomain) ?? SecurityDomains.OfAssetKind(f.AssetKind), B(f.AssetKind)?.ToLowerInvariant(), TierOf(f.Tier)),
    };

    /// An asset on the tier board: its domain (by kind), kind and current tier.
    public static ScopeTarget ForAsset(TierAsset a) => new(SecurityDomains.OfAssetKind(a.AssetKind), B(a.AssetKind)?.ToLowerInvariant(), TierOf(a.Tier));

    /// Records the target on a change about to be staged (exemptions).
    public static StagedChange Stamp(StagedChange c, ScopeTarget t)
    {
        c.Data[DomainKey] = t.Domain; c.Data[KindKey] = t.AssetKind; c.Data[TierKey] = t.Tier;
        return c;
    }

    private static bool Stamped(StagedChange c) => c.Data.ContainsKey(DomainKey);
    private static ScopeTarget StampOf(StagedChange c) => new(B(c.Get(DomainKey)), B(c.Get(KindKey)), B(c.Get(TierKey)));

    /// The action a change is, and what it touches (null targets = not recorded: only an Admin may commit it).
    public static (AccessAction Action, IReadOnlyList<ScopeTarget>? Targets) Of(StagedChange c)
    {
        switch (c.Kind)
        {
            case ChangeKinds.Exemption:
            case ChangeKinds.ExemptionRevoke:
                return (AccessAction.Exempt, Stamped(c) ? new[] { StampOf(c) } : null);
            case ChangeKinds.TierPin:
            {
                var kind = B(c.Get("assetKind"))?.ToLowerInvariant();
                var domain = SecurityDomains.OfAssetKind(kind);
                // the asset leaves its tier AND enters the new one: both must be inside the scope
                return (AccessAction.TierMove, new[] { new ScopeTarget(domain, kind, TierOf(c.Get("fromTier"))), new ScopeTarget(domain, kind, TierOf(c.Get("tier"))) });
            }
            case ChangeKinds.RuleDisable:
                return (AccessAction.Override, new[] { SecurityDomains.OfRuleKey(c.Get("ruleKey")) });
            case ChangeKinds.RuleTier:
            case ChangeKinds.RuleTierReset:
                return (AccessAction.TierMove, new[] { SecurityDomains.OfRuleKey(c.Get("ruleKey")) });
            case ChangeKinds.TemplateRelease:
            case ChangeKinds.TemplateRollback:
                return (AccessAction.Lifecycle, Array.Empty<ScopeTarget>());
            default:
                // documents, connectors, template conformance decisions, and any kind added later: Admin pages
                return (AccessAction.Administer, Array.Empty<ScopeTarget>());
        }
    }

    /// May this user stage / commit this change now?
    public static AccessDecision Check(IAccessScope access, ClaimsPrincipal user, StagedChange c)
    {
        // #404: an undo (Admin: own commits; SuperAdmin: any) or a restore (SuperAdmin) -- the rule lives with the handler
        if (c.Kind == ChangeKinds.ConfigRevert) return SI.Management.Web.ChangeJournal.ConfigRevertHandler.Access(user, c, SI.Management.Web.ChangeJournal.ConfigEntities.Default);
        var (action, targets) = Of(c);
        if (targets is null)
            return user.IsAdmin() ? AccessDecision.Yes : AccessDecision.No("what this change touches was not recorded when it was staged -- only an Admin can commit it; discard it and stage it again");
        return access.CanAll(user, action, targets);
    }
}
