using System.Globalization;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;

namespace SI.Management.Web.DataHealth;

/// <summary>The install's data health state now (CR2, SI #656 -- SecurityInsight only).</summary>
/// <param name="Recorded">A data health cycle has run and the tables exist (an older install: false -- nothing is shown).</param>
/// <param name="State">"Healthy" or "Unhealthy".</param>
/// <param name="Since">When the current state began (UTC).</param>
/// <param name="ConsecutiveAnomalous">Anomalous cycles in a row.</param>
/// <param name="LastCycleAt">When the newest cycle finished (UTC).</param>
public sealed record DataHealthState(bool Recorded, string State, DateTime? Since, int ConsecutiveAnomalous, DateTime? LastCycleAt)
{
    public static readonly DataHealthState None = new(false, "", null, 0, null);
    public bool IsUnhealthy => Recorded && State == "Unhealthy";
}

/// <summary>A SuperAdmin let one data-out channel through while the data is Unhealthy.</summary>
public sealed record DataHealthOverride(long Id, string Channel, string By, string Role, string Reason, DateTime SinceUtc);

/// <summary>One cycle.</summary>
public sealed record DataHealthCycle(long Id, DateTime StartedAt, DateTime? FinishedAt, bool? Anomalous, bool? Complete, string? State, bool? StateChanged, int? Consecutive);

/// <summary>One source's or report's result in a cycle.</summary>
public sealed record DataHealthResult(string Kind, string Name, string Label, long Sampled, long Found, long Missing, long FieldMismatches,
    double? MarginPercent, int? MarginMinimum, long? Allowed, string Verdict, string? Reason);

/// <summary>A record a cycle did not find, or found different.</summary>
public sealed record DataHealthMissing(string Kind, string Name, string? RecordKey, string? RecordName, string? Problem);

/// <summary>Everything the Data health page shows.</summary>
public sealed record DataHealthView(bool HasTables, DataHealthState State, IReadOnlyList<DataHealthOverride> Overrides, IReadOnlyList<DataHealthCycle> Cycles,
    IReadOnlyList<DataHealthResult> Results, IReadOnlyList<DataHealthMissing> Missing, IReadOnlyList<string> Channels)
{
    public static readonly DataHealthView Missing0 = new(false, DataHealthState.None, [], [], [], [], []);
}

/// <summary>
/// THE DATA HEALTH MODEL'S RULES IN THE WEB APP -- the same as the engine (engine\data-health\_shared\SI-DataHealth.ps1):
/// Healthy -> Unhealthy after three anomalous daily cycles in a row, Unhealthy -> Healthy after one good cycle. While
/// Unhealthy every data-out channel plans only; a SuperAdmin lets ONE channel through with a reason (at least 10
/// characters), until the data is Healthy again (the engine clears the overrides then). Written only through
/// cfg.DataHealthOverrideSet.
/// </summary>
public static class DataHealthRules
{
    public const int ReasonMin = 10;

    /// SecurityInsight's own data-out channels (connector names) -- the database's vulnerability connectors come on top.
    public static readonly string[] FixedChannels =
    [
        "servicenow-cmdb", "cmdb-sql", "asset-tagging",
        "data-out-excel-ci", "data-out-excel-findings-detailed", "data-out-excel-findings-summary", "data-out-excel-records",
        "data-out-servicenow-ci", "data-out-servicenow-vulnerable-item",
    ];

    /// PURE. The header's words, or null when there is nothing to show (no cycle has run, or an older install).
    public static string? HeaderText(DataHealthState? s)
    {
        if (s is null || !s.Recorded) return null;
        return s.State == "Unhealthy"
            ? "Unhealthy since " + When(s.Since) + " -- data-out is held"
            : "Healthy" + (s.LastCycleAt is { } t ? " (checked " + When(t) + ")" : "");
    }

    /// PURE. Why an override cannot be saved, or null.
    public static string? Validate(DataHealthState state, string? channel, string? reason, IReadOnlyList<DataHealthOverride> open)
    {
        if (!state.IsUnhealthy) return "Not saved: the data is not Unhealthy, so nothing is held.";
        if (string.IsNullOrWhiteSpace(channel) || channel.Trim().Length > 64) return "Not saved: choose the channel to let through.";
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < ReasonMin) return $"Not saved: say why (at least {ReasonMin} characters; it is on the audit trail).";
        if (open.Any(o => string.Equals(o.Channel, channel.Trim(), StringComparison.OrdinalIgnoreCase))) return "Not saved: this channel is already let through.";
        return null;
    }

    /// PURE. Is a channel held now (Unhealthy, and no open override names it)?
    public static bool IsHeld(DataHealthState state, IReadOnlyList<DataHealthOverride> open, string channel) =>
        state.IsUnhealthy && !open.Any(o => string.Equals(o.Channel, channel, StringComparison.OrdinalIgnoreCase));

    /// PURE. The verdict in words.
    public static string VerdictLabel(string verdict) => verdict switch
    {
        "ok" => "Within margin",
        "anomalous" => "Anomalous",
        "not-checked" => "Not checked",
        "not-used" => "Not used here",
        _ => verdict,
    };

    public static string When(DateTime? t) => t is { } x ? DateTime.SpecifyKind(x, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : "--";
}

public interface IDataHealthStore
{
    Task<DataHealthState> StateAsync(CancellationToken ct);
    Task<DataHealthView> ReadAsync(long? cycleId, CancellationToken ct);
    Task<(bool Saved, string Message)> OverrideAsync(string channel, string reason, string by, string role, CancellationToken ct);
    Task<(bool Saved, string Message)> ClearOverrideAsync(string channel, string by, CancellationToken ct);
}

/// <summary>Reads the data health tables (one-minute cache for the header) and writes overrides through the procedure.</summary>
public sealed class SqlDataHealthStore : IDataHealthStore
{
    private readonly ISqlExecutor _sql;
    private readonly IMemoryCache? _cache;
    private const string Key = "si-data-health";
    public SqlDataHealthStore(ISqlExecutor sql, IMemoryCache? cache = null) { _sql = sql; _cache = cache; }

    public const string StateSql = """
IF OBJECT_ID(N'cfg.DataHealthState') IS NOT NULL SELECT TOP (1) [State], Since, ConsecutiveAnomalous, LastCycleAt FROM cfg.DataHealthState WHERE Id = 1;
""";
    public const string ProbeSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.DataHealthCycle') IS NOT NULL AND OBJECT_ID(N'cfg.DataHealthResult') IS NOT NULL AND OBJECT_ID(N'cfg.DataHealthMissing') IS NOT NULL
             AND OBJECT_ID(N'cfg.DataHealthState') IS NOT NULL AND OBJECT_ID(N'cfg.DataHealthOverride') IS NOT NULL THEN 1 ELSE 0 END AS HasTables
""";
    public const string OverridesSql = "SELECT OverrideId, Channel, SetBy, SetByRole, Reason, SinceUtc FROM cfg.DataHealthOverride WHERE ClearedAt IS NULL ORDER BY SinceUtc DESC;";
    public const string CyclesSql = "SELECT TOP (30) CycleId, StartedAt, FinishedAt, Anomalous, Complete, [State], StateChanged, ConsecutiveAnomalous FROM cfg.DataHealthCycle ORDER BY CycleId DESC;";
    public const string ResultsSql = """
SELECT Kind, Name, Label, Sampled, Found, Missing, FieldMismatches, MarginPercent, MarginMinimum, Allowed, Verdict, Reason
FROM cfg.DataHealthResult WHERE CycleId = @Cycle ORDER BY CASE Kind WHEN N'source' THEN 0 ELSE 1 END, Name;
""";
    public const string MissingSql = "SELECT TOP (2000) Kind, Name, RecordKey, RecordName, Problem FROM cfg.DataHealthMissing WHERE CycleId = @Cycle ORDER BY Kind, Name, RecordName;";
    public const string ChannelsSql = "IF OBJECT_ID(N'cfg.Connector') IS NOT NULL SELECT Name FROM cfg.Connector WHERE Direction = N'vulnerability' ORDER BY Name;";
    public const string OverrideSql = "EXEC cfg.DataHealthOverrideSet @Channel = @Channel, @Reason = @Reason, @By = @By, @Role = @Role, @Clear = @Clear;";

    public async Task<DataHealthState> StateAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue(Key, out DataHealthState? hit) && hit is not null) return hit;
        DataHealthState s;
        try { s = Parse((await _sql.QueryAsync(StateSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()); }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { s = DataHealthState.None; }
        _cache?.Set(Key, s, TimeSpan.FromMinutes(1));
        return s;
    }

    public static DataHealthState Parse(SqlRow? r)
    {
        if (r is null) return DataHealthState.None;
        var st = r.Str("State");
        if (st is not ("Healthy" or "Unhealthy")) return DataHealthState.None;
        return new DataHealthState(true, st, r.Date("Since"), (int)(r.Long("ConsecutiveAnomalous") ?? 0), r.Date("LastCycleAt"));
    }

    private static bool? Bit(SqlRow r, string c) => r.TryGetValue(c, out var v) && v is not null ? Convert.ToBoolean(v, CultureInfo.InvariantCulture) : null;
    private static double? Dbl(SqlRow r, string c) => r.TryGetValue(c, out var v) && v is not null ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;

    public async Task<DataHealthView> ReadAsync(long? cycleId, CancellationToken ct)
    {
        var probe = await _sql.QueryAsync(ProbeSql, new Dictionary<string, object?>(), ct);
        if ((probe.FirstOrDefault()?.Long("HasTables") ?? 0) != 1) return DataHealthView.Missing0;
        _cache?.Remove(Key);
        var state = await StateAsync(ct);
        var ovr = (await _sql.QueryAsync(OverridesSql, new Dictionary<string, object?>(), ct))
            .Select(r => new DataHealthOverride(r.Long("OverrideId") ?? 0, r.Str("Channel") ?? "", r.Str("SetBy") ?? "", r.Str("SetByRole") ?? "SuperAdmin", r.Str("Reason") ?? "", r.Date("SinceUtc") ?? DateTime.MinValue)).ToList();
        var cycles = (await _sql.QueryAsync(CyclesSql, new Dictionary<string, object?>(), ct))
            .Select(r => new DataHealthCycle(r.Long("CycleId") ?? 0, r.Date("StartedAt") ?? DateTime.MinValue, r.Date("FinishedAt"), Bit(r, "Anomalous"), Bit(r, "Complete"),
                r.Str("State"), Bit(r, "StateChanged"), (int?)r.Long("ConsecutiveAnomalous"))).ToList();
        var pick = cycleId is { } want && cycles.Any(c => c.Id == want) ? want : cycles.FirstOrDefault(c => c.FinishedAt is not null)?.Id;
        IReadOnlyList<DataHealthResult> results = [];
        IReadOnlyList<DataHealthMissing> missing = [];
        if (pick is { } p)
        {
            var args = new Dictionary<string, object?> { ["Cycle"] = p };
            results = (await _sql.QueryAsync(ResultsSql, args, ct)).Select(r => new DataHealthResult(r.Str("Kind") ?? "", r.Str("Name") ?? "", r.Str("Label") ?? r.Str("Name") ?? "",
                r.Long("Sampled") ?? 0, r.Long("Found") ?? 0, r.Long("Missing") ?? 0, r.Long("FieldMismatches") ?? 0, Dbl(r, "MarginPercent"), (int?)r.Long("MarginMinimum"),
                r.Long("Allowed"), r.Str("Verdict") ?? "", r.Str("Reason"))).ToList();
            missing = (await _sql.QueryAsync(MissingSql, args, ct)).Select(r => new DataHealthMissing(r.Str("Kind") ?? "", r.Str("Name") ?? "", r.Str("RecordKey"), r.Str("RecordName"), r.Str("Problem"))).ToList();
        }
        var channels = new List<string>(DataHealthRules.FixedChannels);
        try { channels.AddRange((await _sql.QueryAsync(ChannelsSql, new Dictionary<string, object?>(), ct)).Select(r => r.Str("Name")).OfType<string>()); }
        catch (Exception ex) when (ex is not OperationCanceledException) { /* the vulnerability connectors could not be listed: the fixed channels stay */ }
        return new DataHealthView(true, state, ovr, cycles, results, missing, channels.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
    }

    public async Task<(bool Saved, string Message)> OverrideAsync(string channel, string reason, string by, string role, CancellationToken ct)
    {
        await _sql.QueryAsync(OverrideSql, new Dictionary<string, object?>
        {
            ["Channel"] = channel.Trim(), ["Reason"] = reason.Trim().Length > 1000 ? reason.Trim()[..1000] : reason.Trim(), ["By"] = by, ["Role"] = role, ["Clear"] = false,
        }, ct);
        _cache?.Remove(Key);
        return (true, $"{channel.Trim()} is let through until the data is Healthy again.");
    }

    public async Task<(bool Saved, string Message)> ClearOverrideAsync(string channel, string by, CancellationToken ct)
    {
        await _sql.QueryAsync(OverrideSql, new Dictionary<string, object?>
        {
            ["Channel"] = channel.Trim(), ["Reason"] = "taken back", ["By"] = by, ["Role"] = "SuperAdmin", ["Clear"] = true,
        }, ct);
        _cache?.Remove(Key);
        return (true, $"{channel.Trim()} is held again while the data is Unhealthy.");
    }
}
