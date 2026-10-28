using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>
/// This install's update ring as it was RECORDED (#308): cfg.InstallState 'Ring', compact JSON
/// { ring, channel, setBy, source, setAt }, written by setup\Set-SIInstallRing.ps1 (the guided install and
/// Bootstrap-ContainerAppJob.ps1 run it) and by the updater whenever it resolves a ring (engine\_shared\SI-InstallRing.ps1).
/// The ring is a property of the install, known at install time -- so the header can show it before any updater run.
/// </summary>
public sealed record InstallRing(int Ring, string? Channel, string? SetBy, string? Source, DateTime? SetAt);

public sealed class InstallRingReader
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value, UpdatedAt FROM cfg.InstallState WHERE Name = N'Ring';
""";

    /// The setting an admin sets on the Settings page (engine catalog, solution scope): 0..3.
    public const string SettingName = "SI_UpdateRing";

    private readonly ISqlExecutor _sql;
    public InstallRingReader(ISqlExecutor sql) => _sql = sql;

    /// null = nothing recorded.
    public async Task<InstallRing?> ReadAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
        return row is null ? null : Parse(row.Str("Value"));
    }

    /// A ring 0..3 from a number or text ("1", "r1", "ring 1"); null for anything else.
    public static int? RingOf(string? text)
    {
        var t = text?.Trim().Trim('"').Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(t)) return null;
        if (t == "prod") return 3;
        if (t.StartsWith("ring", StringComparison.Ordinal)) t = t[4..].Trim();
        else if (t.StartsWith('r')) t = t[1..];
        return int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 3 ? n : null;
    }

    public static InstallRing? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object || !o.TryGetProperty("ring", out var r)) return null;
            var ring = r.ValueKind switch
            {
                JsonValueKind.Number => r.TryGetInt32(out var n) && n is >= 0 and <= 3 ? n : (int?)null,
                JsonValueKind.String => RingOf(r.GetString()),
                _ => null,
            };
            if (ring is null) return null;
            static string? S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { } s && s.Trim().Length > 0 ? s.Trim() : null;
            DateTime? at = DateTime.TryParse(S(o, "setAt"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            return new InstallRing(ring.Value, S(o, "channel"), S(o, "setBy"), S(o, "source"), at);
        }
        catch (JsonException) { return null; }
    }
}
