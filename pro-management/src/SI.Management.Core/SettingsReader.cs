namespace SI.Management.Core;

public sealed record SettingValue(string Name, string Scope, string? ValueJson, bool IsSecret, DateTimeOffset? UpdatedAt, string UpdatedBy);
public sealed record SettingChange(long ChangeId, string Name, string Scope, string Action, string? OldValue, string? NewValue, DateTimeOffset? ChangedAt, string ChangedBy, string? Reason);
public sealed record SettingsSnapshot(IReadOnlyList<SettingValue> Settings, IReadOnlyList<SettingChange> History);

public interface ISettingsReader
{
    /// Non-secret settings and their change history (Admin only). name = null -> all settings.
    Task<QueryResult<SettingsSnapshot>> ReadAsync(string? name, int historyDays, int historyRows, CancellationToken ct);
}

/// Read-only view of the Pro settings store (cfg.Setting + cfg.ChangeLog). It never returns a secret: a secret
/// row carries only a Key Vault secret NAME in SQL, and this reader withholds even that.
public sealed class SettingsReader : ISettingsReader
{
    private readonly ISqlReader _sql;
    private readonly TimeProvider _clock;

    public SettingsReader(ISqlReader sql, TimeProvider? clock = null)
    {
        _sql = sql;
        _clock = clock ?? TimeProvider.System;
    }

    public async Task<QueryResult<SettingsSnapshot>> ReadAsync(string? name, int historyDays, int historyRows, CancellationToken ct)
    {
        var n = QueryParameters.SettingName(name);
        var days = QueryParameters.Days(historyDays);
        var limit = QueryParameters.HistoryRows(historyRows);
        var since = _clock.GetUtcNow().UtcDateTime.Date.AddDays(-days);

        var pCur = new Dictionary<string, object?> { ["name"] = n };
        var pHist = new Dictionary<string, object?> { ["name"] = n, ["since"] = since, ["limit"] = limit };

        var cur = await _sql.QueryAsync(QueryTemplates.SettingsCurrent, pCur, ct).ConfigureAwait(false);
        var hist = await _sql.QueryAsync(QueryTemplates.SettingsHistory, pHist, ct).ConfigureAwait(false);

        var settings = cur.Select(r =>
        {
            var secret = Cell.Int(r, "IsSecret") == 1;
            return new SettingValue(Cell.Str(r, "Name"), Cell.Str(r, "Scope"), secret ? null : NullIfEmpty(Cell.Str(r, "ValueJson")), secret,
                Cell.Time(r, "UpdatedAt"), Cell.Str(r, "UpdatedBy"));
        }).ToList();
        var history = hist.Select(r => new SettingChange((long)Cell.Dbl(r, "ChangeId"), Cell.Str(r, "Name"), Cell.Str(r, "Scope"), Cell.Str(r, "Action"),
            Redact(Cell.Str(r, "OldValue")), Redact(Cell.Str(r, "NewValue")), Cell.Time(r, "ChangedAt"), Cell.Str(r, "ChangedBy"),
            NullIfEmpty(Cell.Str(r, "Reason")))).ToList();

        var query = EstateQueries.DescribeSql(QueryTemplates.SettingsCurrent, pCur) + "\n;\n" + EstateQueries.DescribeSql(QueryTemplates.SettingsHistory, pHist);
        return new(new SettingsSnapshot(settings, history), query, _sql.SourceName, _clock.GetUtcNow());
    }

    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;

    // Belt and braces: the SQL already redacts these.
    private static string? Redact(string s) =>
        s.Length == 0 ? null : s.StartsWith("keyvault:", StringComparison.OrdinalIgnoreCase) ? "(Key Vault reference)" : s;
}
