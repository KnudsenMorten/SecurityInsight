namespace SIAnalyzer.Web.Services;

/// <summary>
/// Where the scheduler keeps its cross-replica send markers (audit #9). Bound from
/// "SIAnalyzer:Schedule". Holds NO secrets - the table is reached with the app's Managed
/// Identity.
///
/// Same storage account as the governance register, a DIFFERENT table: scheduler bookkeeping is
/// not a governance record. The deploy derives both endpoints from one <c>-StorageAccountId</c>
/// so they cannot drift apart, and one "Storage Table Data Contributor" grant covers both.
///
/// Unset =&gt; the scheduler falls back to a process-local marker and says so at startup, because
/// without a shared marker #9's two failure modes (double-send across replicas, silently skipped
/// window after a restart) are both still live.
/// </summary>
public sealed class ScheduleStorageOptions
{
    public const string SectionName = "SIAnalyzer:Schedule";

    /// <summary>Azure Table Storage endpoint, e.g.
    /// <c>https://stsecurityinsight.table.core.windows.net</c>. Empty =&gt; in-memory markers.</summary>
    public string TableEndpoint { get; set; } = "";

    /// <summary>Table name inside that account. One row per scheduled job.</summary>
    public string TableName { get; set; } = "sischedule";
}
