using SI.Management.Web.Data;

namespace SI.Management.Web.Support;

/// #1021 (framework SECAUDIT-1a): the THIRD revoker of the Invardia Support app's just-in-time database grant. The grant job
/// (caj-si-support-grant) sweeps on every start and the heartbeat job on every tick; the web app runs all the time, so it
/// sweeps too -- every 5 minutes, through the signed procedure cfg.SupportGrantSweep (its only right on the support grant:
/// EXECUTE on that one procedure). A grant past its maxUntil is removed even when both jobs are stopped. The procedure only
/// removes what an EXPIRED grant added; it never touches the read-only access or anything else. A database without the
/// procedure (the admin step has not run yet), or no database at all, is quietly nothing to do.
public sealed class SupportGrantSweep(ISqlExecutor sql, ILogger<SupportGrantSweep> log) : BackgroundService
{
    public static readonly TimeSpan First = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan Every = TimeSpan.FromMinutes(5);

    public const string SweepSql = """
IF OBJECT_ID(N'cfg.SupportGrantSweep') IS NULL BEGIN SELECT 0 AS Closed, 0 AS RolesRemoved; RETURN; END
EXEC cfg.SupportGrantSweep @By = N'web app';
""";

    /// One pass. Returns the number of expired grant markers closed (0 when there was nothing to do or it could not run).
    public async Task<long> RunOnceAsync(CancellationToken ct)
    {
        var rows = await sql.QueryAsync(SweepSql, new Dictionary<string, object?>(), ct);
        var first = rows.FirstOrDefault();
        var closed = first?.Long("Closed") ?? 0;
        if (closed > 0) log.LogInformation("support access: {Closed} expired support grant(s) closed, {Removed} role membership(s) removed", closed, first?.Long("RolesRemoved") ?? 0);
        return closed;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var wait = First;
        var said = false;
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(wait, stoppingToken); } catch (OperationCanceledException) { return; }
            wait = Every;
            try { await RunOnceAsync(stoppingToken); said = false; }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // said once until it works again: the jobs sweep too, so this is never the only revoker
                if (!said) log.LogWarning(ex, "support access: the expired-grant sweep could not run (the support grant job and the heartbeat sweep too)");
                said = true;
            }
        }
    }
}
