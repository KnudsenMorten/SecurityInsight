using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>One kind of update (code or templates): the last manifest the updater checked and what it did with it.
/// <see cref="Wave"/> (CR3, #657): the pre-release wave the code this install runs was served for (null = the ring's own
/// release) -- Invardia serves a wave member a version released to a lower ring early, with no ring move.</summary>
public sealed record UpdateKindState(string Kind, string? Version, long? Sequence, int? Ring, string? Action, long? Applied, string? Hold,
                                     string? Wave = null, string? WaveVersion = null, int? WaveRing = null)
{
    public string Summary
    {
        get
        {
            if (string.IsNullOrEmpty(Action)) return "not checked yet";
            // the feed's ring channel (#350) has no sequence -- a build is named by its version (3.0.0-rc.42)
            var m = string.IsNullOrEmpty(Version) ? "no manifest"
                  : Sequence is null ? $"{Version} (ring {Ring})"
                  : $"{Version} (sequence {Sequence}, ring {Ring})";
            var a = Applied is >= 0 ? $"; applied sequence {Applied}" : "";
            return $"{m} -- {Action}{a}";
        }
    }
}

/// <summary>
/// The update state the updater keeps (#240): where updates come from (Invardia or SI's own feed), the last manifest per
/// kind (version, sequence, ring), the last check and any HOLD. The updater writes it as compact JSON into
/// cfg.InstallState 'UpdateState' (the install key is never in it); this page only reads it.
/// </summary>
public sealed record UpdateState(string Source, DateTime? LastCheckUtc, UpdateKindState? Code, UpdateKindState? Templates,
                                 string? Claim, string? Error, DateTime? UpdatedAt, string? ClaimAgain = null, DateTime? ClaimAgainUtc = null)
{
    public IEnumerable<string> Holds => new[] { Code, Templates }.Where(k => k is not null && !string.IsNullOrEmpty(k.Hold)).Select(k => $"{k!.Kind}: {k.Hold}");
    public bool Refused => new[] { Code, Templates }.Any(k => k?.Action == "refused");
    public string SourceText => Source switch
    {
        "invardia" => "Invardia (signed manifests)",
        // SI #750 (b): a Community edition install's in-cloud updater (container/updater/_shared/SI-UpdaterCommunity.ps1)
        "community" => "The signed Community channel (GitHub releases)",
        "feed" => "SecurityInsight's own update feed (internal test path)",
        _ => "not recorded",
    };
}

public sealed class UpdateStateReader
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value, UpdatedAt FROM cfg.InstallState WHERE Name = N'UpdateState';
""";

    private static readonly string[] Sources = { "invardia", "community", "feed" };
    private readonly ISqlExecutor _sql;
    public UpdateStateReader(ISqlExecutor sql) => _sql = sql;

    /// null = nothing recorded (no updater has run on this install).
    public async Task<UpdateState?> ReadAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
        return row is null ? null : Parse(row.Str("Value"), row.Date("UpdatedAt"));
    }

    /// A wave name as the updater records it: trimmed, at most 60 characters of letters, digits, space and . _ ( ) + -;
    /// anything else is not a wave name (null) -- the same rule as engine\_shared\SI-ReleaseControl.ps1.
    public static string? WaveName(string? value)
    {
        var v = value?.Trim();
        return v is { Length: > 0 and <= 60 } && System.Text.RegularExpressions.Regex.IsMatch(v, @"^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,59}$") ? v : null;
    }

    public static UpdateState? Parse(string? json, DateTime? updatedAt)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return null;
            static string? S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            static long? L(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var x) ? x : null;
            UpdateKindState? K(string kind)
            {
                if (!o.TryGetProperty(kind, out var k) || k.ValueKind != JsonValueKind.Object) return null;
                var ring = L(k, "ring");
                // CR3 (#657): the wave of the applied code -- { name, version, ring } (the updater writes it only while there is one)
                string? wave = null, waveVersion = null; int? waveRing = null;
                if (k.TryGetProperty("wave", out var w) && w.ValueKind == JsonValueKind.Object)
                {
                    wave = WaveName(S(w, "name"));
                    if (wave is not null) { waveVersion = S(w, "version"); waveRing = L(w, "ring") is { } wr and >= 0 and <= 3 ? (int)wr : null; }
                }
                return new UpdateKindState(kind, S(k, "version"), L(k, "sequence"), ring is null ? null : (int)ring, S(k, "action"), L(k, "applied"), S(k, "hold"),
                                           wave, waveVersion, waveRing);
            }
            var source = S(o, "source") ?? "";
            if (!Sources.Contains(source)) source = "";
            DateTime? last = DateTime.TryParse(S(o, "lastCheckUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            DateTime? again = DateTime.TryParse(S(o, "claimAgainUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var a) ? a : null;
            return new UpdateState(source, last, K("code"), K("templates"), S(o, "claim"), S(o, "error"), updatedAt, S(o, "claimAgain"), again);
        }
        catch (JsonException) { return null; }
    }
}
