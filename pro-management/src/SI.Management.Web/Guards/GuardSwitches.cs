using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Guards;

/// <summary>
/// #414 (operator, 2026-10-06: "give me settings for ALL gates, so I can turn them off and fine tune them") -- the guard
/// switches, the SAME settings the engines read (engine\_shared\SI-Guard.ps1, Test-SIGuardOn): one master switch
/// SI_Guards_Enabled and, per guard in config\guard-catalog.locked.json, SI_Guard_&lt;Token&gt;_Enabled and
/// SI_Guard_&lt;Token&gt;_Mail -- the master ON by default, each guard ON unless the catalog marks it "defaultOff" (Settings &gt; Guards). &lt;Token&gt; is the id in PascalCase
/// ('exemption.bulk.refused' -&gt; 'ExemptionBulkRefused'). Read with a one-minute cache from any scope (a solution-scope
/// value wins); when they cannot be read every guard is ON (the safe default).
/// </summary>
public sealed class GuardSwitches
{
    public const string Master = "SI_Guards_Enabled";

    /// #448 (operator: "turn off these in all env worldwide") and the guard relief (owner 2026-10-11: two brakes only): the
    /// guards that are OFF until an install switches them on -- the same list as "defaultOff": true in
    /// config\guard-catalog.locked.json (GuardSwitchesTests keeps them equal). Only the CI retire brake (cmdb.sql.collapse,
    /// cmdb.handoff.mass-change) and the duplicates brake (vuln.connector.target-incomplete) are on by default.
    public static readonly IReadOnlySet<string> DefaultOff = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "vuln.connector.close-ceiling", "vuln.connector.empty-snapshot", "vuln.connector.collapse", "vuln.connector.scope-changed",
        "vuln.connector.run-incomplete", "vuln.connector.snapshot-incomplete", "vuln.connector.refused",
        "cmdb.sql.snapshot-incomplete", "cmdb.sql.empty-snapshot", "cmdb.sql.no-correlation-map", "cmdb.sql.stale",
        "cmdb.servicenow.unreachable", "cmdb.servicenow.create-gate", "cmdb.servicenow.service-model",
        "asset.properties.collection-change",
        "datasync.collection.held", "datasync.collection.refused", "datasync.asset.kind-dropped", "datasync.collection.short-read",
        "ra.output.row-drop", "ra.output.column-emptied", "ingest.rows.short-count",
        "schema.gate.refused", "update.schema.failed", "licence.state.invalid", "licence.state.grace",
        "audit.retention.refused", "exemption.bulk.refused",
        "flow.run.catch-up", "flow.step.skipped", "flow.step.start-failed", "flow.step.interrupted",
        "job.execution.previous-running", "job.run.throttled-stuck",
    };

    /// PURE. 'vuln.connector.close-ceiling' -&gt; 'VulnConnectorCloseCeiling' (as ConvertTo-SIGuardSettingToken).
    public static string Token(string guardId) =>
        string.Concat(guardId.Split('.', '-').Where(p => p.Length > 0).Select(p => char.ToUpperInvariant(p[0]) + p[1..]));

    public static string EnabledName(string guardId) => $"SI_Guard_{Token(guardId)}_Enabled";
    public static string MailName(string guardId) => $"SI_Guard_{Token(guardId)}_Mail";

    private readonly ISettingsStoreReader _reader;
    private readonly IMemoryCache _cache;
    private readonly ILogger<GuardSwitches> _log;

    public GuardSwitches(ISettingsStoreReader reader, IMemoryCache cache, ILogger<GuardSwitches> log) { _reader = reader; _cache = cache; _log = log; }

    /// Is this guard on? The master switch AND the guard's own switch; on when they cannot be read.
    public async Task<bool> IsOnAsync(string guardId, CancellationToken ct) => IsOn(await RowsAsync(ct), guardId);

    private async Task<IReadOnlyList<SettingRow>> RowsAsync(CancellationToken ct)
    {
        if (_cache.TryGetValue("si-guard-switches", out IReadOnlyList<SettingRow>? hit) && hit is not null) return hit;
        try
        {
            var rows = (await _reader.ReadSettingsAsync(ct)).Rows.Where(r => r.Name.StartsWith("SI_Guard", StringComparison.OrdinalIgnoreCase)).ToList();
            _cache.Set("si-guard-switches", (IReadOnlyList<SettingRow>)rows, TimeSpan.FromMinutes(1));
            return rows;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the guard switches could not be read -- every guard stays on");
            return Array.Empty<SettingRow>();
        }
    }

    /// PURE. The guard is on unless the master or its own switch is off (false / 0 / off / no / disabled).
    public static bool IsOn(IEnumerable<SettingRow> rows, string guardId)
    {
        var list = rows.OrderBy(r => r.Scope == "solution" ? 0 : 1).ToList();
        bool Flag(string name, bool byDefault = true)
        {
            var row = list.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
            var v = row?.ValueJson is { } j ? Parse(j) : null;
            if (string.IsNullOrWhiteSpace(v)) return byDefault;
            return v.Trim().Trim('$').ToLowerInvariant() is not ("false" or "0" or "off" or "no" or "disabled");
        }
        return Flag(Master) && Flag(EnabledName(guardId), !DefaultOff.Contains(guardId));
    }

    private static string? Parse(string json)
    {
        try
        {
            using var d = JsonDocument.Parse(json);
            return d.RootElement.ValueKind switch
            {
                JsonValueKind.String => d.RootElement.GetString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Null => null,
                _ => d.RootElement.GetRawText(),
            };
        }
        catch (JsonException) { return json; }
    }
}
