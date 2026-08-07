namespace SIAnalyzer.Core.Governance;

/// <summary>The outcome of a governance write attempt - fail-soft + honest about whether a
/// platform was (or, while locked, was NOT) touched.</summary>
public sealed record GovernanceResult(bool Accepted, bool PlatformSynced, string Detail, string? RecordId = null);

/// <summary>
/// The central governance register + append-only audit trail (Phase 6). It is the ONLY write
/// surface in SIA. Two write kinds: a local risk-accept comment, and an exemption (recorded
/// locally; platform sync is GATED by <see cref="GovernanceCapabilities"/> and refused while
/// the lock holds - the no-auto-revoke rule). Reads (the register, the audit, accepted-state
/// display) are always available.
///
/// AUDIT #7 (2026-08-05) - this class no longer holds the records. It holds the RULES and
/// delegates storage to <see cref="IGovernancePersistence"/>, so the same gate semantics,
/// validation, audit trail and lifecycle apply whether records live in Azure Table Storage
/// (the hosted deployment) or in RAM (demo/local/tests). Before this, three
/// <c>List&lt;&gt;</c>s in a singleton meant every risk-acceptance, exemption and audit line
/// died on restart/redeploy and diverged between replicas, while the page presented the result
/// as a register of record.
///
/// Reads go to persistence every time rather than through a cached working set - a cache would
/// bring the per-replica divergence straight back, and the register is tens-to-hundreds of rows.
/// </summary>
public sealed class GovernanceStore
{
    private readonly object _lock = new();
    private readonly IGovernancePersistence _store;
    private readonly GovernanceCapabilities _caps;
    private readonly Func<DateTimeOffset> _now;

    public GovernanceStore(GovernanceCapabilities caps, IGovernancePersistence? persistence = null, Func<DateTimeOffset>? now = null)
    {
        _caps = caps;
        _store = persistence ?? new InMemoryGovernancePersistence();
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public GovernanceCapabilities Capabilities => _caps;

    /// <summary>Where the register is kept, and whether that survives a restart. Surfaced in the
    /// GUI + API so a volatile store is never presented as a register of record.</summary>
    public string StorageDescription => _store.Description;
    public bool StorageIsDurable => _store.IsDurable;

    // --- Reads (always allowed) ---------------------------------------------

    public IReadOnlyList<RiskAcceptComment> Comments => _store.GetComments();

    public IReadOnlyList<ExemptionRecord> Exemptions => _store.GetExemptions();

    public IReadOnlyList<AuditEntry> Audit => _store.GetAudit();

    /// <summary>Whether a finding is currently risk-accepted (for read-only display on the
    /// worklist/reports). Always available regardless of the write flags.
    ///
    /// 🔴 AUDIT #8: this compares <c>ExpiryUtc</c> to now ITSELF rather than trusting the
    /// lifecycle state. The sweep that flips a record to Expired runs on a timer, so a record
    /// can be past its expiry but still marked Recorded - and before this fix an expired
    /// acceptance kept suppressing a finding indefinitely, because nothing ever ran the sweep.
    /// The displayed state must not depend on a background job having fired.</summary>
    public bool IsRiskAccepted(string findingId) =>
        Comments.Any(c => c.FindingId == findingId && IsActive(c.State, c.ExpiryUtc));

    /// <summary>Whether a finding is currently covered by an unexpired exemption. The mirror of
    /// <see cref="IsRiskAccepted"/> - the audit's #8 named only risk-accept, but the exemption
    /// register had no read path at all either.</summary>
    public bool IsExempt(string findingId) =>
        Exemptions.Any(e => e.FindingId == findingId && IsActive(e.State, e.ExpiryUtc));

    /// <summary>The governance state of one finding for display: what it is, who accepted it,
    /// why, and until when. Returns <see cref="GovernanceFindingState.None"/> when the finding
    /// carries no active record.</summary>
    public GovernanceFindingState GetFindingState(string findingId)
    {
        var exemption = Exemptions.FirstOrDefault(e => e.FindingId == findingId && IsActive(e.State, e.ExpiryUtc));
        if (exemption is not null)
        {
            return new GovernanceFindingState(false, true, exemption.Owner, exemption.Reason, exemption.ExpiryUtc);
        }
        var accepted = Comments.FirstOrDefault(c => c.FindingId == findingId && IsActive(c.State, c.ExpiryUtc));
        return accepted is null
            ? GovernanceFindingState.None
            : new GovernanceFindingState(true, false, accepted.Owner, accepted.Justification, accepted.ExpiryUtc);
    }

    /// <summary>Governance state for many findings at once - one persistence read instead of
    /// one per row, so annotating a 100-row worklist does not become 200 store round-trips.</summary>
    public IReadOnlyDictionary<string, GovernanceFindingState> GetFindingStates(IEnumerable<string> findingIds)
    {
        var comments = Comments;
        var exemptions = Exemptions;
        var map = new Dictionary<string, GovernanceFindingState>(StringComparer.Ordinal);
        foreach (var id in findingIds)
        {
            if (string.IsNullOrEmpty(id) || map.ContainsKey(id)) continue;
            var exemption = exemptions.FirstOrDefault(e => e.FindingId == id && IsActive(e.State, e.ExpiryUtc));
            if (exemption is not null)
            {
                map[id] = new GovernanceFindingState(false, true, exemption.Owner, exemption.Reason, exemption.ExpiryUtc);
                continue;
            }
            var accepted = comments.FirstOrDefault(c => c.FindingId == id && IsActive(c.State, c.ExpiryUtc));
            if (accepted is not null)
            {
                map[id] = new GovernanceFindingState(true, false, accepted.Owner, accepted.Justification, accepted.ExpiryUtc);
            }
        }
        return map;
    }

    /// <summary>A record counts as active while it is not marked Expired AND its expiry (if it
    /// has one) is still in the future. A risk-accept comment with no expiry never lapses.</summary>
    private bool IsActive(GovernanceState state, DateTimeOffset? expiry) =>
        state != GovernanceState.Expired && (expiry is null || expiry > _now());

    // --- Local writes (risk-accept comment) ---------------------------------

    /// <summary>Record a risk-accept comment in SIA's OWN store (no platform touched). Refused
    /// when the local register is off (fully read-only deploy).</summary>
    public GovernanceResult AddRiskAcceptComment(string findingId, string configurationName, string owner, string justification, DateTimeOffset? expiry = null)
    {
        if (!_caps.LocalRegisterEnabled)
            return new GovernanceResult(false, false, "The governance register is read-only here (SIAnalyzer:Governance:LocalRegisterEnabled is off).");
        if (string.IsNullOrWhiteSpace(justification))
            return new GovernanceResult(false, false, "A justification is required to risk-accept a finding.");
        if (expiry is { } e && e <= _now())
            return new GovernanceResult(false, false, "An expiry date, if given, must be in the future.");

        var rec = new RiskAcceptComment
        {
            Id = NewId("rac"),
            FindingId = findingId,
            ConfigurationName = configurationName,
            Owner = owner,
            Justification = justification,
            CreatedUtc = _now(),
            ExpiryUtc = expiry,
            State = GovernanceState.Recorded,
        };
        lock (_lock)
        {
            _store.UpsertComment(rec);
            Log(owner, "risk-accept", $"{configurationName} ({findingId}): {justification}");
        }
        return new GovernanceResult(true, false, "Risk-accept comment recorded (local store only; no platform written).", rec.Id);
    }

    // --- Exemptions (recorded locally; platform sync GATED) -----------------

    /// <summary>
    /// Record an exemption in SIA's register and ATTEMPT to sync it to the requested platforms.
    /// The local record is written when the register is on; the PLATFORM sync is refused while
    /// <see cref="GovernanceCapabilities.PlatformSyncEnabled"/> is false (locked) - the result
    /// is honest that nothing was suppressed on any platform (the no-auto-revoke guarantee).
    /// </summary>
    public GovernanceResult RecordExemption(string findingId, string configurationName, string scope, string owner, string reason, DateTimeOffset expiry, IReadOnlyList<GovernancePlatform> syncTargets)
    {
        if (!_caps.LocalRegisterEnabled)
            return new GovernanceResult(false, false, "The governance register is read-only here (SIAnalyzer:Governance:LocalRegisterEnabled is off).");
        if (string.IsNullOrWhiteSpace(reason))
            return new GovernanceResult(false, false, "A reason is required for an exemption.");
        if (expiry <= _now())
            return new GovernanceResult(false, false, "An exemption must have a future expiry date (expiry/renewal is mandatory).");

        // The platform write is the gated part. While locked, NEVER push to a platform.
        var willSync = _caps.PlatformSyncEnabled && syncTargets.Count > 0;

        var rec = new ExemptionRecord
        {
            Id = NewId("exm"),
            FindingId = findingId,
            ConfigurationName = configurationName,
            Scope = scope,
            Owner = owner,
            Reason = reason,
            CreatedUtc = _now(),
            ExpiryUtc = expiry,
            State = GovernanceState.Recorded,
            SyncTargets = syncTargets,
            Synced = willSync,
        };
        lock (_lock)
        {
            _store.UpsertExemption(rec);
            Log(owner, "exemption-record", $"{configurationName} ({findingId}) scope={scope} expires={expiry:yyyy-MM-dd} targets=[{string.Join(",", syncTargets)}]");
            if (willSync)
            {
                // Reserved for the post-test build: push to the platform via the configured
                // connector. Unreachable while PlatformSyncLocked = true.
                Log(owner, "exemption-sync", $"{rec.Id} synced to [{string.Join(",", syncTargets)}]");
            }
            else if (syncTargets.Count > 0)
            {
                Log(owner, "exemption-sync-skipped", $"{rec.Id} NOT synced: {_caps.PlatformSyncDisabledReason}");
            }
        }

        return willSync
            ? new GovernanceResult(true, true, "Exemption recorded and synced to the platform.", rec.Id)
            : new GovernanceResult(true, false, "Exemption recorded locally. Platform sync was NOT performed: " + _caps.PlatformSyncDisabledReason, rec.Id);
    }

    /// <summary>Renew an exemption with a new (future) expiry - the renewal workflow.</summary>
    public GovernanceResult RenewExemption(string exemptionId, DateTimeOffset newExpiry, string actor)
    {
        if (!_caps.LocalRegisterEnabled)
            return new GovernanceResult(false, false, "The governance register is read-only here.");
        if (newExpiry <= _now())
            return new GovernanceResult(false, false, "Renewal needs a future expiry date.");
        lock (_lock)
        {
            var existing = _store.GetExemptions().FirstOrDefault(e => e.Id == exemptionId);
            if (existing is null) return new GovernanceResult(false, false, "No such exemption.");
            _store.UpsertExemption(existing with { ExpiryUtc = newExpiry, State = GovernanceState.Renewed });
            Log(actor, "exemption-renew", $"{exemptionId} -> expires {newExpiry:yyyy-MM-dd}");
        }
        return new GovernanceResult(true, false, "Exemption renewed.", exemptionId);
    }

    /// <summary>Mark every past-expiry record Expired (the expiry sweep). Returns the count
    /// flipped. Read-safe to call any time; it only changes lifecycle state, never a platform.
    ///
    /// This is a DISPLAY concern only: <see cref="IsRiskAccepted"/> and <see cref="IsExempt"/>
    /// already compare the expiry themselves, so suppression stops on time even if the sweep
    /// never runs. Running it twice (two replicas, overlapping timers) is harmless - the second
    /// pass finds nothing left to flip.</summary>
    public int SweepExpired()
    {
        var now = _now();
        var n = 0;
        lock (_lock)
        {
            foreach (var e in _store.GetExemptions())
            {
                if (e.State != GovernanceState.Expired && e.ExpiryUtc <= now)
                {
                    _store.UpsertExemption(e with { State = GovernanceState.Expired });
                    Log("system", "exemption-expired", e.Id);
                    n++;
                }
            }
            foreach (var c in _store.GetComments())
            {
                if (c.State != GovernanceState.Expired && c.ExpiryUtc is { } ex && ex <= now)
                {
                    _store.UpsertComment(c with { State = GovernanceState.Expired });
                    Log("system", "risk-accept-expired", c.Id);
                    n++;
                }
            }
        }
        return n;
    }

    private void Log(string actor, string action, string detail) =>
        _store.AppendAudit(new AuditEntry { TimestampUtc = _now(), Actor = actor, Action = action, Detail = detail });

    /// <summary>
    /// AUDIT #18: was <c>$"{prefix}-{Guid.NewGuid():N}".Substring(0, 16)</c> - a 4-char prefix plus
    /// just 12 hex chars, so 48 bits of the GUID kept and the rest discarded.
    ///
    /// This stopped being cosmetic when audit #7 made the register DURABLE. The id becomes the
    /// Azure Table <b>RowKey</b>, and records are written with
    /// <c>UpsertEntity(..., TableUpdateMode.Replace)</c> - so a collision does not error, it
    /// SILENTLY REPLACES an existing risk-acceptance or exemption. Losing a governance decision
    /// without a trace is not a maintainability issue.
    ///
    /// The full GUID costs 20 more characters against a 1 KB RowKey budget. Existing short ids keep
    /// working untouched - ids are only ever compared for equality, never parsed or length-checked,
    /// and a read takes the id straight back from the RowKey - so there is nothing to migrate.
    /// </summary>
    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}";
}
