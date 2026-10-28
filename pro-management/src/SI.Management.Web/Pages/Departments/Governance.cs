using SI.Management.Web.Departments;

namespace SI.Management.Web.Pages.Departments;

/// <summary>
/// The governance block of a department page (#254, phase 2): how many of its findings have which status, what is planned
/// for a maintenance window (and whether that window has passed), and the newest log entries. Read from cfg.GovernanceState
/// / cfg.GovernanceEntry -- one row per finding, not the whole log. A database without the tables shows the setup step.
/// </summary>
public sealed record DepartmentGovernance(IReadOnlyDictionary<string, long> Counts, IReadOnlyList<GovernanceStateRow> Planned,
    IReadOnlyList<GovernanceEntryRow> Recent, string? Note)
{
    public const int RecentShown = 25;

    public static async Task<DepartmentGovernance?> LoadAsync(IServiceProvider? services, int departmentId, CancellationToken ct)
    {
        if (services?.GetService(typeof(GovernanceRepository)) is not GovernanceRepository repo) return null;
        try
        {
            if (!await repo.TablesExistAsync(ct))
                return new(new Dictionary<string, long>(), [], [], "The governance log needs the Pro settings schema applied again (sql\\si-pro-settings.sql; it only adds).");
            var counts = await repo.DepartmentStatusCountsAsync(departmentId, ct);
            var planned = (await repo.DepartmentStatesAsync(departmentId, 200, ct)).Where(s => s.ScheduledFor is not null && s.Status == SI.Management.Core.ProData.GovernanceStatuses.Planned).ToList();
            var recent = await repo.DepartmentLogAsync(departmentId, RecentShown, ct);
            return new(counts, planned, recent, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(new Dictionary<string, long>(), [], [], "The governance log could not be read: " + ex.Message);
        }
    }
}
