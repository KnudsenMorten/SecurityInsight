using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;

namespace SI.Management.Web.Guards;

/// <summary>The install's guard mode now (CR4, SI #654; framework §12.11b GUARD-STRICT).</summary>
/// <param name="Mode">"strict" while the stricter period lasts, else "normal".</param>
/// <param name="Recorded">The updater recorded an engine fingerprint (an older install: false -- nothing is shown).</param>
/// <param name="Until">The end of the stricter period (UTC): its start + 24 hours.</param>
/// <param name="Version">The release that started it.</param>
/// <param name="StrictFrom">Its start (UTC) -- with <paramref name="Hash"/> the period an early end names.</param>
/// <param name="Hash">The engine fingerprint the period belongs to.</param>
/// <param name="EndedEarlyAt">A SuperAdmin ended this period early (UTC).</param>
/// <param name="EndedBy">Who ended it.</param>
/// <param name="EndedByRole">The role that ended it (SuperAdmin).</param>
/// <param name="Reason">Why it was ended.</param>
public sealed record GuardModeState(string Mode, bool Recorded, DateTime? Until, string? Version, DateTime? StrictFrom, string? Hash,
    DateTime? EndedEarlyAt, string? EndedBy, string? EndedByRole, string? Reason)
{
    public static readonly GuardModeState Normal = new("normal", false, null, null, null, null, null, null, null, null);
    public bool IsStrict => Mode == "strict";
    /// A period that a SuperAdmin ended early and that would still run without that (the header and the page say so).
    public bool EndedEarly => EndedEarlyAt is not null && Until is { } u && u > DateTime.UtcNow;
}

/// <summary>
/// STRICTER SAFETY CHECKS FOR 24 HOURS AFTER A RELEASE THAT CHANGED ENGINE CODE -- the same rules as the engines
/// (engine\_shared\SI-GuardStrict.ps1). The updater records the engine fingerprint of the code it installed in
/// cfg.InstallState 'EngineFingerprint' { hash, version, since, strictFrom, strictVersion }; a changed fingerprint sets
/// strictFrom and starts the period; the first fingerprint an install records starts nothing. While it lasts every
/// numbered limit is halved from the CONFIGURED value: max(1, floor(configured x 0.5)), never above it (1 stays 1, 0 = no
/// limit stays 0). A SuperAdmin may end the period early with a reason (cfg.InstallState 'GuardStrictEnd', written only
/// through cfg.GuardStrictEndSet; audited guard.strict.end-early); an end names the period it ends, so it never ends a
/// later one.
/// </summary>
public static class GuardModeRules
{
    public const int Hours = 24;
    public const string FingerprintRow = "EngineFingerprint";
    public const string EndRow = "GuardStrictEnd";
    /// The shortest reason a SuperAdmin gives for ending the period early.
    public const int ReasonMin = 10;

    /// PURE. The mode from the two rows' JSON (either may be null) at <paramref name="nowUtc"/>.
    public static GuardModeState Compute(string? fingerprintJson, string? endJson, DateTime nowUtc)
    {
        var fp = Parse(fingerprintJson);
        var hash = Str(fp, "hash")?.ToLowerInvariant();
        if (hash is null || hash.Length != 64 || !hash.All(Uri.IsHexDigit)) return GuardModeState.Normal;
        var recorded = GuardModeState.Normal with { Recorded = true, Hash = hash };
        if (Time(fp, "strictFrom") is not { } from) return recorded;
        var until = from.AddHours(Hours);
        if (nowUtc >= until || nowUtc < from.AddMinutes(-5)) return recorded;
        var version = Str(fp, "strictVersion");
        var end = Parse(endJson);
        if (end is not null && string.Equals(Str(end, "hash"), hash, StringComparison.OrdinalIgnoreCase)
            && Time(end, "strictFrom") is { } ef && Math.Abs((ef - from).TotalSeconds) < 1 && Time(end, "endedAt") is { } ea)
            return new GuardModeState("normal", true, until, version, from, hash, ea, Str(end, "by"), Str(end, "role") ?? "SuperAdmin", Str(end, "reason"));
        return new GuardModeState("strict", true, until, version, from, hash, null, null, null, null);
    }

    /// PURE. One limit while strict: max(1, floor(configured x 0.5)), never above the configured value; 0 or less stays.
    public static double Halve(double configured)
    {
        if (double.IsNaN(configured) || configured <= 0) return configured;
        return Math.Min(configured, Math.Max(1, Math.Floor(configured * 0.5)));
    }

    /// PURE. The limit in force: halved while strict, else as configured.
    public static double Effective(double configured, GuardModeState? mode) => mode?.IsStrict == true ? Halve(configured) : configured;

    /// PURE. "10 -> 5 while strict" ('' when the limit is not halved).
    public static string LimitText(double configured, GuardModeState? mode, string unit = "")
    {
        var e = Effective(configured, mode);
        if (e == configured) return "";
        var u = string.IsNullOrEmpty(unit) ? "" : " " + unit;
        return string.Create(CultureInfo.InvariantCulture, $"{configured:0.##}{u} -> {e:0.##}{u} while strict");
    }

    /// PURE. The header's words: "Strict until 2026-10-15 14:00 UTC (release 3.0.1)", "Normal (ended early by SuperAdmin
    /// ...)", or null when there is nothing to show (normal, or nothing recorded).
    public static string? HeaderText(GuardModeState? m)
    {
        if (m is null || !m.Recorded) return null;
        if (m.IsStrict) return "Strict until " + GuardReleaseText.When(m.Until) + (string.IsNullOrWhiteSpace(m.Version) ? "" : " (release " + m.Version + ")");
        if (m.EndedEarly) return "Normal (strict ended early by " + (m.EndedByRole ?? "SuperAdmin") + ", " + GuardReleaseText.When(m.EndedEarlyAt) + ")";
        return null;
    }

    /// PURE. The calm sentence for the Guards page.
    public static string Sentence(GuardModeState m) =>
        "Stricter period" + (string.IsNullOrWhiteSpace(m.Version) ? " after a recent release" : " after release " + m.Version) + " until " + GuardReleaseText.When(m.Until)
        + ": the safety checks' limits are halved for 24 hours after a release that changed the engine, as planned. After the period the normal limits apply again by themselves.";

    /// PURE. The row a SuperAdmin's early end writes (at most 400 characters: the reason is shortened, the audit keeps it whole).
    public static string EndJson(GuardModeState m, DateTime endedAtUtc, string by, string role, string reason)
    {
        string Build(string r) => JsonSerializer.Serialize(new Dictionary<string, string?>
        {
            ["hash"] = m.Hash, ["strictFrom"] = Iso(m.StrictFrom), ["endedAt"] = Iso(endedAtUtc), ["by"] = by, ["role"] = role, ["reason"] = r,
        });
        var text = (reason ?? "").Trim();
        var json = Build(text);
        while (json.Length > 400 && text.Length > 0) { text = text[..Math.Max(0, text.Length - Math.Max(10, json.Length - 400))]; json = Build(text.Length > 0 ? text + "..." : ""); }
        return json;
    }

    public static string? Iso(DateTime? t) => t is { } x ? DateTime.SpecifyKind(x, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) : null;

    private static JsonElement? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { using var d = JsonDocument.Parse(json); return d.RootElement.ValueKind == JsonValueKind.Object ? d.RootElement.Clone() : null; }
        catch (JsonException) { return null; }
    }

    private static string? Str(JsonElement? o, string name) =>
        o is { } e && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { } s && s.Trim().Length > 0 ? s.Trim() : null;

    private static DateTime? Time(JsonElement? o, string name) =>
        DateTime.TryParse(Str(o, name), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
}

/// <summary>Reads the guard mode (one-minute cache) and records a SuperAdmin's early end through cfg.GuardStrictEndSet.</summary>
public sealed class GuardModeReader
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Name, Value FROM cfg.InstallState WHERE Name IN (N'EngineFingerprint', N'GuardStrictEnd');
""";
    public const string EndSql = "EXEC cfg.GuardStrictEndSet @Value = @Value, @By = @By;";
    private const string Key = "si-guard-mode";

    private readonly ISqlExecutor _sql;
    private readonly IMemoryCache? _cache;
    private readonly ILogger<GuardModeReader>? _log;
    public GuardModeReader(ISqlExecutor sql, IMemoryCache? cache = null, ILogger<GuardModeReader>? log = null) { _sql = sql; _cache = cache; _log = log; }

    /// The mode now; Normal when nothing is recorded or nothing can be read (never throws but for a cancel).
    public async Task<GuardModeState> ReadAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue(Key, out GuardModeState? hit) && hit is not null) return hit;
        GuardModeState m;
        try
        {
            var rows = await _sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
            string? Val(string n) => rows.FirstOrDefault(r => string.Equals(r.Str("Name"), n, StringComparison.Ordinal))?.Str("Value");
            m = GuardModeRules.Compute(Val(GuardModeRules.FingerprintRow), Val(GuardModeRules.EndRow), DateTime.UtcNow);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { _log?.LogDebug(ex, "the guard mode could not be read -- normal"); m = GuardModeState.Normal; }
        _cache?.Set(Key, m, TimeSpan.FromMinutes(1));
        return m;
    }

    /// Ends the current stricter period early (the caller checked the role and the reason). Returns the row written.
    public async Task<string> EndEarlyAsync(GuardModeState current, string by, string role, string reason, CancellationToken ct)
    {
        if (!current.IsStrict) throw new InvalidOperationException("the safety checks are not in a stricter period -- nothing to end");
        var json = GuardModeRules.EndJson(current, DateTime.UtcNow, by, role, reason);
        await _sql.QueryAsync(EndSql, new Dictionary<string, object?> { ["Value"] = json, ["By"] = by }, ct);
        Forget();
        return json;
    }

    public void Forget() => _cache?.Remove(Key);
}
