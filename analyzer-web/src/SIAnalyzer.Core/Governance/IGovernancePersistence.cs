namespace SIAnalyzer.Core.Governance;

/// <summary>
/// Where the governance register actually LIVES (audit #7). <see cref="GovernanceStore"/> owns
/// every rule - the capability gates, the justification/expiry validation, the audit trail, the
/// lifecycle - and delegates storage to this interface, so there is exactly ONE copy of the rules
/// no matter where the records are kept.
///
/// Two implementations ship: <see cref="InMemoryGovernancePersistence"/> (demo/local/tests, NOT
/// durable) and the Azure Table Storage one in SIAnalyzer.Web. The seam exists because
/// SIAnalyzer.Core deliberately carries no Azure SDK - it stays pure logic, testable offline.
///
/// 🔴 The store reads through this interface on EVERY read rather than caching a working set.
/// That is deliberate: a cache would reintroduce the second half of #7 (replicas diverging), and
/// a governance register is tens-to-hundreds of rows, not a hot path.
///
/// Implementations must be thread-safe. The audit trail is APPEND-ONLY - there is no update or
/// delete for it, which is the whole point of an audit trail.
/// </summary>
public interface IGovernancePersistence
{
    /// <summary>Human-readable description of where records are kept, for the honest
    /// "where does this live" note on the governance page.</summary>
    string Description { get; }

    /// <summary>Whether records survive a restart, a redeploy and a second replica. False for
    /// the in-memory implementation - and the UI says so rather than implying a register of
    /// record.</summary>
    bool IsDurable { get; }

    IReadOnlyList<RiskAcceptComment> GetComments();
    IReadOnlyList<ExemptionRecord> GetExemptions();

    /// <summary>The audit trail, newest first.</summary>
    IReadOnlyList<AuditEntry> GetAudit(int max = 500);

    /// <summary>Insert or replace a risk-accept comment (insert, expiry flip).</summary>
    void UpsertComment(RiskAcceptComment comment);

    /// <summary>Insert or replace an exemption (insert, renewal, expiry flip).</summary>
    void UpsertExemption(ExemptionRecord exemption);

    /// <summary>Append one audit line. Never updates or deletes an existing one.</summary>
    void AppendAudit(AuditEntry entry);
}

/// <summary>
/// The non-durable implementation: three in-RAM lists. This is what SIA ran on before audit #7,
/// and it stays the right choice for demo mode, local development and the offline test suite -
/// but it is NOT a register of record, and <see cref="IsDurable"/> returning false is what makes
/// the UI say so out loud instead of presenting a volatile list as durable.
/// </summary>
public sealed class InMemoryGovernancePersistence : IGovernancePersistence
{
    private readonly object _lock = new();
    private readonly List<RiskAcceptComment> _comments = new();
    private readonly List<ExemptionRecord> _exemptions = new();
    private readonly List<AuditEntry> _audit = new();

    public string Description => "in-memory (this instance only)";
    public bool IsDurable => false;

    public IReadOnlyList<RiskAcceptComment> GetComments()
    {
        lock (_lock) return _comments.ToList();
    }

    public IReadOnlyList<ExemptionRecord> GetExemptions()
    {
        lock (_lock) return _exemptions.ToList();
    }

    public IReadOnlyList<AuditEntry> GetAudit(int max = 500)
    {
        lock (_lock) return _audit.OrderByDescending(a => a.TimestampUtc).Take(max).ToList();
    }

    public void UpsertComment(RiskAcceptComment comment)
    {
        lock (_lock)
        {
            var i = _comments.FindIndex(c => c.Id == comment.Id);
            if (i < 0) _comments.Add(comment); else _comments[i] = comment;
        }
    }

    public void UpsertExemption(ExemptionRecord exemption)
    {
        lock (_lock)
        {
            var i = _exemptions.FindIndex(e => e.Id == exemption.Id);
            if (i < 0) _exemptions.Add(exemption); else _exemptions[i] = exemption;
        }
    }

    public void AppendAudit(AuditEntry entry)
    {
        lock (_lock) _audit.Add(entry);
    }
}
