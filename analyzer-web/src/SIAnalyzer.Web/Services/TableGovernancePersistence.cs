using Azure;
using Azure.Data.Tables;
using SIAnalyzer.Core.Governance;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// The DURABLE governance register (audit #7): Azure Table Storage, one entity per record,
/// reached with the app's Managed Identity. Survives a restart, a redeploy and a scale-out, and
/// two replicas see the same register because every read goes to the table.
///
/// One table, three partitions - <c>riskaccept</c>, <c>exemption</c>, <c>audit</c>. Audit rows
/// are INSERTED and never updated or deleted (the trail's whole point); the other two are
/// upserted so a renewal or an expiry flip replaces the record in place.
///
/// The audit RowKey is a reverse-ticks key, so Table Storage's ascending RowKey order returns
/// the trail newest-first without a sort or a full scan.
///
/// 🔴 This class is deliberately a thin MAPPING layer: no rules, no validation, no lifecycle -
/// those all live in <see cref="GovernanceStore"/>, which is fully covered offline. What CANNOT
/// be verified offline is the Azure round-trip itself; the entity mapping below is unit-tested
/// (round-trip through <see cref="ToEntity(RiskAcceptComment)"/> / <see cref="ToComment"/>) but
/// the first proof it can actually reach the table is the hosted live-verify gate.
/// </summary>
public sealed class TableGovernancePersistence : IGovernancePersistence
{
    internal const string RiskAcceptPartition = "riskaccept";
    internal const string ExemptionPartition = "exemption";
    internal const string AuditPartition = "audit";

    private readonly TableClient _table;
    private readonly string _description;

    public TableGovernancePersistence(TableClient table, string description)
    {
        _table = table;
        _description = description;
    }

    public string Description => _description;
    public bool IsDurable => true;

    public IReadOnlyList<RiskAcceptComment> GetComments() =>
        _table.Query<TableEntity>(e => e.PartitionKey == RiskAcceptPartition).Select(ToComment).ToList();

    public IReadOnlyList<ExemptionRecord> GetExemptions() =>
        _table.Query<TableEntity>(e => e.PartitionKey == ExemptionPartition).Select(ToExemption).ToList();

    public IReadOnlyList<AuditEntry> GetAudit(int max = 500) =>
        _table.Query<TableEntity>(e => e.PartitionKey == AuditPartition, maxPerPage: Math.Min(max, 1000))
              .Take(max)                     // RowKey is reverse-ticks, so this IS newest-first
              .Select(ToAudit)
              .ToList();

    public void UpsertComment(RiskAcceptComment comment) =>
        _table.UpsertEntity(ToEntity(comment), TableUpdateMode.Replace);

    public void UpsertExemption(ExemptionRecord exemption) =>
        _table.UpsertEntity(ToEntity(exemption), TableUpdateMode.Replace);

    public void AppendAudit(AuditEntry entry)
    {
        // Append-only: AddEntity, never Upsert. A RowKey collision (same tick, two replicas)
        // would otherwise silently overwrite someone else's audit line, so retry with a fresh
        // key instead of losing the entry.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                _table.AddEntity(ToEntity(entry));
                return;
            }
            catch (RequestFailedException ex) when (ex.Status == 409)
            {
                // EntityAlreadyExists - try again with a new random suffix.
            }
        }
        throw new InvalidOperationException("Could not append the governance audit entry after 5 attempts (RowKey collisions).");
    }

    // --- Mapping (record <-> TableEntity) -----------------------------------
    // Kept internal so the offline tests can round-trip it without touching Azure.

    internal static TableEntity ToEntity(RiskAcceptComment c) => new(RiskAcceptPartition, c.Id)
    {
        ["FindingId"] = c.FindingId,
        ["ConfigurationName"] = c.ConfigurationName,
        ["Owner"] = c.Owner,
        ["Justification"] = c.Justification,
        ["CreatedUtc"] = c.CreatedUtc.UtcDateTime,
        ["ExpiryUtc"] = c.ExpiryUtc?.UtcDateTime,
        ["State"] = c.State.ToString(),
    };

    internal static RiskAcceptComment ToComment(TableEntity e) => new()
    {
        Id = e.RowKey,
        FindingId = e.GetString("FindingId") ?? "",
        ConfigurationName = e.GetString("ConfigurationName") ?? "",
        Owner = e.GetString("Owner") ?? "",
        Justification = e.GetString("Justification") ?? "",
        CreatedUtc = ReadDate(e, "CreatedUtc") ?? default,
        ExpiryUtc = ReadDate(e, "ExpiryUtc"),
        State = ReadState(e),
    };

    internal static TableEntity ToEntity(ExemptionRecord x) => new(ExemptionPartition, x.Id)
    {
        ["FindingId"] = x.FindingId,
        ["ConfigurationName"] = x.ConfigurationName,
        ["Scope"] = x.Scope,
        ["Owner"] = x.Owner,
        ["Reason"] = x.Reason,
        ["CreatedUtc"] = x.CreatedUtc.UtcDateTime,
        ["ExpiryUtc"] = x.ExpiryUtc.UtcDateTime,
        ["State"] = x.State.ToString(),
        // A short comma-separated list, not JSON - it is read straight back into the enum list.
        ["SyncTargets"] = string.Join(",", x.SyncTargets),
        ["Synced"] = x.Synced,
    };

    internal static ExemptionRecord ToExemption(TableEntity e) => new()
    {
        Id = e.RowKey,
        FindingId = e.GetString("FindingId") ?? "",
        ConfigurationName = e.GetString("ConfigurationName") ?? "",
        Scope = e.GetString("Scope") ?? "",
        Owner = e.GetString("Owner") ?? "",
        Reason = e.GetString("Reason") ?? "",
        CreatedUtc = ReadDate(e, "CreatedUtc") ?? default,
        ExpiryUtc = ReadDate(e, "ExpiryUtc") ?? default,
        State = ReadState(e),
        SyncTargets = ReadTargets(e),
        Synced = e.GetBoolean("Synced") ?? false,
    };

    internal static TableEntity ToEntity(AuditEntry a) => new(AuditPartition, AuditRowKey(a.TimestampUtc))
    {
        ["TimestampUtc"] = a.TimestampUtc.UtcDateTime,
        ["Actor"] = a.Actor,
        ["Action"] = a.Action,
        ["Detail"] = a.Detail,
    };

    internal static AuditEntry ToAudit(TableEntity e) => new()
    {
        TimestampUtc = ReadDate(e, "TimestampUtc") ?? default,
        Actor = e.GetString("Actor") ?? "",
        Action = e.GetString("Action") ?? "",
        Detail = e.GetString("Detail") ?? "",
    };

    /// <summary>Reverse-ticks + a random suffix: ascending RowKey order == newest first, and two
    /// entries written in the same tick still get distinct keys.</summary>
    internal static string AuditRowKey(DateTimeOffset ts) =>
        $"{DateTime.MaxValue.Ticks - ts.UtcDateTime.Ticks:D19}-{Guid.NewGuid():N}".Substring(0, 27);

    private static DateTimeOffset? ReadDate(TableEntity e, string key)
    {
        var v = e.GetDateTimeOffset(key);
        return v is null ? null : new DateTimeOffset(v.Value.UtcDateTime, TimeSpan.Zero);
    }

    private static GovernanceState ReadState(TableEntity e) =>
        Enum.TryParse<GovernanceState>(e.GetString("State"), ignoreCase: true, out var s) ? s : GovernanceState.Recorded;

    private static IReadOnlyList<GovernancePlatform> ReadTargets(TableEntity e)
    {
        var raw = e.GetString("SyncTargets");
        if (string.IsNullOrWhiteSpace(raw)) return Array.Empty<GovernancePlatform>();
        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                  .Select(t => Enum.TryParse<GovernancePlatform>(t, ignoreCase: true, out var p) ? (GovernancePlatform?)p : null)
                  .Where(p => p is not null)
                  .Select(p => p!.Value)
                  .ToList();
    }
}
