using Microsoft.Extensions.DependencyInjection;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Changes;

/// <summary>
/// #865 (owner 2026-10-21: "every page that depends on a feature that is off or has not run yet ... says so plainly instead of
/// '0' / 'No data'"): WHY Changes &amp; trends &gt; Vulnerabilities over time / Vulnerabilities per collection may be empty --
/// SecurityInsight's own SQL vulnerability target (<see cref="ConnectorRepository.IsOwnSqlTarget"/>, `vulnerability-sql`) is
/// what records every vulnerability's lifecycle; when it is missing, switched off, in test mode, has not run yet or its last
/// run failed, the pages say so (with what to do), never a bare 0. Read from cfg.Connector + cfg.ConnectorRun.
/// </summary>
public static class OwnSqlTargetStatus
{
    public const string Lead = "SecurityInsight's own SQL vulnerability target (the close-loop that records every vulnerability's lifecycle) ";

    /// PURE. The plain sentence, or null when the own SQL target is on and its last run went through.
    public static string? Explain(IReadOnlyList<ConnectorRow> connectors, IReadOnlyList<ConnectorRunRow> runs)
    {
        var own = connectors.Where(c => ConnectorRepository.IsOwnSqlTarget(c.Kind, c.Direction))
            .OrderByDescending(c => c.Enabled).ThenBy(c => c.Name, StringComparer.Ordinal).FirstOrDefault();
        if (own is null)
            return Lead + "is not set up, so nothing is recorded here and these numbers stay 0. Set it up under Connectors (Get Started's connectors step).";
        if (!own.Enabled)
            return Lead + $"'{own.Name}' is switched off, so nothing is recorded here and these numbers stay 0. Switch it on under Connectors.";
        if (own.Mode != "apply" || !own.AllowCreate || !own.AllowClose)
            return Lead + $"'{own.Name}' is in test mode (whatif, or it may not create / close), so it records nothing and these numbers stay 0. The next update turns it on; or save it under Connectors (it saves as apply).";
        var last = runs.Where(r => r.ConnectorName == own.Name).OrderByDescending(r => r.StartedAt ?? DateTime.MinValue).FirstOrDefault();
        if (last is null)
            return Lead + $"'{own.Name}' has not run yet -- the numbers appear after its first run (the vulnerability close-loop job).";
        if (last.Outcome is "failed" or "refused" or "halted")
            return Lead + $"'{own.Name}': its last run ({Fmt.When(last.StartedAt)}) {last.Outcome}" + (string.IsNullOrWhiteSpace(last.Error ?? last.HaltReason) ? "" : $" -- {(last.Error ?? last.HaltReason)!.Trim()}") + ". What it did not record is missing here until a run goes through.";
        if (last.Outcome == "whatif")
            return Lead + $"'{own.Name}': its last run ({Fmt.When(last.StartedAt)}) was a test run (whatif) and recorded nothing. The next run records.";
        return null;
    }

    /// The sentence for the signed-in page, or null (on, healthy, or no connector store -- a read that fails is logged, never shown as a fact).
    public static async Task<string?> ReadAsync(IServiceProvider? services, ILogger log, CancellationToken ct)
    {
        if (services?.GetService<ConnectorRepository>() is not { } repo) return null;
        try
        {
            if (!await repo.TableExistsAsync(ct)) return null;
            var rows = await repo.ListAsync(ct);
            var own = rows.Where(c => ConnectorRepository.IsOwnSqlTarget(c.Kind, c.Direction)).OrderByDescending(c => c.Enabled).ThenBy(c => c.Name, StringComparer.Ordinal).FirstOrDefault();
            var runs = own is null ? Array.Empty<ConnectorRunRow>() : await repo.RunsAsync(own.Name, 5, ct);
            return Explain(rows, runs);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the own SQL vulnerability target's state could not be read");
            return null;
        }
    }
}
