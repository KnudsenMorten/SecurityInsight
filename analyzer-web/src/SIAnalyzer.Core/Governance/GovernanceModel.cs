namespace SIAnalyzer.Core.Governance;

/// <summary>
/// The governance domain (Phase 6) - the ONLY sanctioned write path in SIA. Everything else
/// stays strictly read-only. Two record kinds live in the central register:
///   * a <see cref="RiskAcceptComment"/> - an owner marks a finding "risk-accepted" with a
///     justification; the worklist/reports reflect the accepted state without deleting the
///     finding. DISPLAY of accepted state is always allowed (read).
///   * an <see cref="ExemptionRecord"/> - a scoped, expiring exemption that MAY be synced to
///     Azure Defender-for-Cloud / Azure Policy / Defender XDR. The platform-WRITING sync is
///     the GATED part (see <see cref="GovernanceCapabilities"/>): it ships OFF and locked.
///
/// CRITICAL no-auto-revoke rule: an exemption that syncs to a platform SUPPRESSES/removes a
/// finding there. Until the sync is fully tested, no build may be able to ENABLE it - the
/// capability is hard-locked OFF, surfaced in the GUI visible-but-dimmed.
/// </summary>
public enum GovernanceKind
{
    RiskAcceptComment,
    Exemption,
}

/// <summary>The lifecycle state of a governance record.</summary>
public enum GovernanceState
{
    /// <summary>Recorded in SIA; for an exemption, NOT yet pushed to any platform.</summary>
    Recorded,
    /// <summary>Approved by the approval gate (still local until/unless synced).</summary>
    Approved,
    /// <summary>Past its expiry date - needs renewal or it lapses.</summary>
    Expired,
    /// <summary>Renewed with a new expiry.</summary>
    Renewed,
}

/// <summary>The platforms an exemption can (eventually, once enabled) sync to.</summary>
public enum GovernancePlatform
{
    DefenderForCloud,
    AzurePolicy,
    DefenderXdr,
}

/// <summary>An owner's risk-acceptance of a finding (a comment + justification). Display is a
/// read concern (always allowed); persisting one is a governance write to the SIA store only
/// (it never touches MDE/Entra/ARM).</summary>
public sealed record RiskAcceptComment
{
    public required string Id { get; init; }
    public required string FindingId { get; init; }
    public required string ConfigurationName { get; init; }
    public required string Owner { get; init; }
    public required string Justification { get; init; }
    public DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset? ExpiryUtc { get; init; }
    public GovernanceState State { get; init; } = GovernanceState.Recorded;
}

/// <summary>A scoped, expiring exemption. <see cref="SyncTargets"/> records WHERE it is meant
/// to apply once platform sync is enabled; <see cref="Synced"/> stays false in this build
/// because the sync capability is locked off.</summary>
public sealed record ExemptionRecord
{
    public required string Id { get; init; }
    public required string FindingId { get; init; }
    public required string ConfigurationName { get; init; }
    public required string Scope { get; init; }
    public required string Owner { get; init; }
    public required string Reason { get; init; }
    public DateTimeOffset CreatedUtc { get; init; }
    public required DateTimeOffset ExpiryUtc { get; init; }
    public GovernanceState State { get; init; } = GovernanceState.Recorded;
    public IReadOnlyList<GovernancePlatform> SyncTargets { get; init; } = Array.Empty<GovernancePlatform>();
    /// <summary>Whether this exemption has been pushed to its platforms. Always false in a
    /// build where platform sync is locked off (the no-auto-revoke rule).</summary>
    public bool Synced { get; init; }
}

/// <summary>
/// The governance state of ONE finding, for display on the worklist / reports (audit #8:
/// "the worklist/reports reflect the accepted state without deleting the finding"). An exempt
/// finding reports Exempt; otherwise an unexpired risk-acceptance reports RiskAccepted; a
/// finding with neither is <see cref="None"/>. Expired records never appear here.
/// </summary>
public sealed record GovernanceFindingState(
    bool RiskAccepted,
    bool Exempt,
    string? Owner,
    string? Reason,
    DateTimeOffset? ExpiryUtc)
{
    /// <summary>The finding carries no active governance record.</summary>
    public static readonly GovernanceFindingState None = new(false, false, null, null, null);

    public bool HasRecord => RiskAccepted || Exempt;

    /// <summary>The badge text for a worklist/report row. Empty when there is no record - the
    /// finding then renders exactly as before. A governed finding is MARKED, never hidden and
    /// never removed from the score.</summary>
    public string Label => Exempt ? "Exempt" : RiskAccepted ? "Risk-accepted" : "";
}

/// <summary>One immutable audit-trail line. The register keeps a full, append-only trail of
/// every governance action (who / what / when) for accountability.</summary>
public sealed record AuditEntry
{
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string Actor { get; init; }
    public required string Action { get; init; }
    public required string Detail { get; init; }
}
