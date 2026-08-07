using Azure;
using Azure.Data.Tables;
using SIAnalyzer.Core.Scheduling;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// The DURABLE send-marker store (audit #9): one Azure Table row per scheduled job, claimed with
/// ETag optimistic concurrency so exactly one replica wins a window.
///
/// The interlock, in full:
///   * no row yet      -> AddEntity. A 409 means another replica created it first, so re-read.
///   * row exists      -> if its window is >= the one being claimed, someone already handled it:
///                        return false. Otherwise UpdateEntity with If-Match on the ETag we read;
///                        a 412 means another replica updated it in between, so we lost: false.
///
/// It is a separate table from the governance register on purpose. Scheduler bookkeeping is not
/// a governance record, and the register's audit trail should not be sharing a table with a job
/// marker - same storage account, same MI grant, different concerns.
///
/// 🔴 As with the governance table, the AZURE ROUND-TRIP is not verifiable offline. The claim
/// SEMANTICS are covered by the in-memory implementation's tests; the mapping is covered here;
/// the first proof that two real replicas interlock is the hosted live-verify gate.
/// </summary>
public sealed class TableSendMarkerStore : ISendMarkerStore
{
    internal const string MarkerPartition = "sendmarker";
    internal const string WindowColumn = "WindowUtc";
    internal const string ClaimedColumn = "ClaimedUtc";
    internal const string ClaimedByColumn = "ClaimedBy";

    private readonly TableClient _table;
    private readonly string _description;
    private readonly string _instance;

    public TableSendMarkerStore(TableClient table, string description, string? instanceId = null)
    {
        _table = table;
        _description = description;
        // Recorded on the row purely so an operator can see WHICH replica sent the mail.
        _instance = instanceId ?? Environment.MachineName;
    }

    public string Description => _description;
    public bool IsDurable => true;

    public DateTimeOffset? GetLastHandled(string jobName)
    {
        var existing = TryRead(jobName);
        return existing is null ? null : ReadWindow(existing);
    }

    public bool TryClaim(string jobName, DateTimeOffset window)
    {
        var existing = TryRead(jobName);

        if (existing is null)
        {
            try
            {
                _table.AddEntity(NewEntity(jobName, window, _instance));
                return true;
            }
            catch (RequestFailedException ex) when (ex.Status == 409)
            {
                // Another replica created the row between our read and our insert. Re-read and
                // fall through to the update path rather than assuming we won.
                existing = TryRead(jobName);
                if (existing is null) return false;
            }
        }

        var handled = ReadWindow(existing);
        if (handled is not null && handled >= window) return false;   // already done by someone

        var updated = NewEntity(jobName, window, _instance);
        try
        {
            _table.UpdateEntity(updated, existing.ETag, TableUpdateMode.Replace);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == 412)
        {
            return false;   // lost the race - another replica claimed this window first
        }
    }

    private TableEntity? TryRead(string jobName)
    {
        try
        {
            return _table.GetEntity<TableEntity>(MarkerPartition, jobName).Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    // --- Mapping (kept internal so the offline tests can exercise it) -------

    internal static TableEntity NewEntity(string jobName, DateTimeOffset window, string instance) =>
        new(MarkerPartition, jobName)
        {
            [WindowColumn] = window.UtcDateTime,
            [ClaimedColumn] = DateTimeOffset.UtcNow.UtcDateTime,
            [ClaimedByColumn] = instance,
        };

    internal static DateTimeOffset? ReadWindow(TableEntity entity)
    {
        var v = entity.GetDateTimeOffset(WindowColumn);
        return v is null ? null : new DateTimeOffset(v.Value.UtcDateTime, TimeSpan.Zero);
    }
}
