using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Collection;

/// <summary>
/// #1396 DATA GETTING OLD (owner 2026-11-26: "why have nobody found out" / "fix it"): one install had no complete pipeline
/// run for eight days and others were 1.5 to 2.5 days behind. Every page showed the last complete run as it should
/// (ONE TRUSTED RUN), but nothing said it was getting old. Now, when NO NEW DATA has been published for longer than
/// SI_Pro_StaleDataWarnHours (default 36; 0 = off), a WARNING says so in plain words:
///   * on Home (the wall board, with the menu or full screen) for everyone who sees it -- worded for a reader (and the
///     Wallboard screen), or for an Admin with the way to the runs;
///   * at the top of EVERY page for an Admin, with the newest whole-pipeline run's result and failed step (the run record)
///     and why the newest run was not shown (the publish's own reason).
/// THE AGE is counted from when the shown collection became COMPLETE (its own LoadedAt, which a later republish of the same
/// collection never resets) -- not from its collection time, which is set near the run's START: on a large install a
/// healthy run can take more than 12 hours from start to publish (two-agent check 2026-11-26). Unknown = its collection time.
/// A warning only: nothing is held, stopped or hidden. The engine has the same rule (engine\_shared\SI-StaleData.ps1).
/// </summary>
public static class StaleDataWarning
{
    public const string Setting = "SI_Pro_StaleDataWarnHours";
    public const int DefaultHours = 36;
    /// The page the warning sends an Admin to: the pipeline's runs.
    public const string RunsPage = "/Admin/Jobs";
    public const string HomePage = "/Wallboard";

    /// PURE. The limit from the setting rows (solution scope first): a whole number >= 0; not set or not valid = 36.
    public static int HoursFrom(IEnumerable<SettingRow> rows)
    {
        var row = rows.Where(r => string.Equals(r.Name, Setting, StringComparison.OrdinalIgnoreCase))
                      .OrderBy(r => r.Scope == "solution" ? 0 : 1).FirstOrDefault();
        if (row?.ValueJson is not { Length: > 0 } json) return DefaultHours;
        string? text;
        try
        {
            using var doc = JsonDocument.Parse(json);
            text = doc.RootElement.ValueKind switch
            {
                JsonValueKind.Number => doc.RootElement.GetRawText(),
                JsonValueKind.String => doc.RootElement.GetString(),
                _ => null,
            };
        }
        catch (JsonException) { text = json; }
        return int.TryParse(text?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var h) && h >= 0 ? h : DefaultHours;
    }

    /// PURE. Since when the shown data is there: when its collection became Complete, else its collection time.
    public static DateTime? Since(PublishedRunState state) =>
        state.ShownCompletedTime is { } done ? DateTime.SpecifyKind(done, DateTimeKind.Utc)
        : state.ShownTime is { } t ? DateTime.SpecifyKind(t, DateTimeKind.Utc) : null;

    /// PURE. The warning, or null: off (0), nothing shown yet, or not older than the limit (exactly at the limit does not
    /// warn yet). <paramref name="lastRun"/> = the newest whole-pipeline run record (or null).
    public static StaleDataNotice? Evaluate(PublishedRunState state, int warnHours, DateTime nowUtc, FlowRun? lastRun)
    {
        if (warnHours <= 0 || state.ShownTime is not { } shown || Since(state) is not { } since) return null;
        var age = nowUtc - since;
        if (age.TotalHours <= warnHours) return null;
        return new StaleDataNotice(DateTime.SpecifyKind(shown, DateTimeKind.Utc), since, age, warnHours, RunLine(lastRun),
            string.IsNullOrWhiteSpace(state.RefusedWhy) ? null : Cut(state.RefusedWhy.Trim()));
    }

    /// PURE. Who sees it where: an Admin on every page; a reader and the Wallboard screen on Home (the wall board) only.
    public static bool Shown(bool isAdmin, bool isReader, bool isWallboard, string currentPage) =>
        isAdmin || ((isReader || isWallboard) && string.Equals(currentPage, HomePage, StringComparison.OrdinalIgnoreCase));

    /// PURE. "37 hours" below two days, else "8 days" (whole, rounded down).
    public static string Age(TimeSpan age) =>
        age.TotalHours < 48 ? $"{(long)Math.Floor(age.TotalHours)} hours" : $"{(long)Math.Floor(age.TotalDays)} days";

    /// PURE. The newest run in one plain sentence. Null = no run record.
    ///   "A run is in progress (started ...)." / "The last run failed on ... at step x: <its error>." / "The last run was
    ///   stopped on ...: <why>." / "The last run completed on ..., but its data was not published." (the reason follows)
    public static string? RunLine(FlowRun? run)
    {
        if (run is null) return null;
        static string When(DateTimeOffset? t) => t is { } v ? SI.Management.Web.Pages.LocalTime.Text(v) : "an unknown time";
        var state = run.State ?? "";
        var on = When(run.EndedUtc ?? run.HeartbeatUtc ?? run.StartedUtc);
        string Reason() => string.IsNullOrWhiteSpace(run.StopReason) ? "." : ": " + Cut(run.StopReason).TrimEnd('.') + ".";
        switch (state)
        {
            case "Running":
                return $"A run is in progress (started {When(run.StartedUtc)}).";
            case "Cancelled" or "Stopped" or "Interrupted":
                return $"The last run was stopped on {on}{Reason()}";
            case "Success" or "Succeeded":
                return $"The last run completed on {on}, but its data was not published.";
        }
        var bad = run.Steps.Where(s => s.State is "Failed" or "TimedOut" or "Interrupted" && s.ErrorClass is not "cancelled").OrderBy(s => s.Order).FirstOrDefault();
        if (bad is not null)
            return $"The last run failed on {on} at step {bad.Job}" + (string.IsNullOrWhiteSpace(bad.Error) ? "." : ": " + Cut(bad.Error).TrimEnd('.') + ".");
        if (state is "Failed" or "TimedOut")
            return $"The last run failed on {on}{Reason()}";
        return $"The last run ended on {on}{Reason()}";
    }

    private static string Cut(string s)
    {
        var t = string.Join(' ', s.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return t.Length > 300 ? t[..297] + "..." : t;
    }
}

/// <summary>What the warning says (no internal names). The times are "yyyy-MM-dd HH:mm UTC": the page shows them in the
/// viewer's own zone (data-utc).</summary>
public sealed record StaleDataNotice(DateTime NewestCompleteUtc, DateTime SinceUtc, TimeSpan Age, int LimitHours, string? RunLine, string? NotShownWhy)
{
    /// "The newest complete data is from 2026-11-18 03:00 UTC. No new data has been published since then (8 days)."
    public string Lead => $"The newest complete data is from {SI.Management.Web.Pages.LocalTime.Text(NewestCompleteUtc)}. No new data has been published since then ({StaleDataWarning.Age(Age)}).";

    /// An Admin: the way to the runs (the menu path of <paramref name="runsPath"/>).
    public string AdminText(string runsPath) => $"{Lead} See {runsPath}.";

    /// Anyone else (a reader, the Wallboard screen): what it means for the figures, and who can see why.
    public string ReaderText(string runsPath) =>
        $"{Lead} The figures on these pages are from that time. An administrator can see why under {runsPath}.";

    /// The reason, for an Admin: the newest run's result and failed step, and why the newest run was not shown.
    public IEnumerable<string> AdminDetail()
    {
        if (RunLine is { Length: > 0 } r) yield return r;
        if (NotShownWhy is { Length: > 0 } w) yield return "Why the newest run is not shown: " + w.TrimEnd('.') + ".";
    }
}

/// <summary>The warning for the layouts. One small read of the settings, kept for <see cref="SqlStaleDataNotices.Ttl"/>; the
/// run record is read only when the data IS old. NEVER throws: the run state not readable = no warning (logged); the
/// settings not readable = the default limit (36 hours), never "no warning".</summary>
public interface IStaleDataNotices
{
    Task<StaleDataNotice?> CurrentAsync(CancellationToken ct);
}

public sealed class SqlStaleDataNotices : IStaleDataNotices
{
    public static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);
    private const string CacheKey = "stale-data-notice";

    private readonly IPublishedRunNotices _published;
    private readonly ISettingsStoreReader _settings;
    private readonly IFlowStore _flow;
    private readonly IMemoryCache? _cache;
    private readonly TimeProvider _clock;
    private readonly ILogger<SqlStaleDataNotices>? _log;

    public SqlStaleDataNotices(IPublishedRunNotices published, ISettingsStoreReader settings, IFlowStore flow, IMemoryCache? cache = null,
        TimeProvider? clock = null, ILogger<SqlStaleDataNotices>? log = null)
    { _published = published; _settings = settings; _flow = flow; _cache = cache; _clock = clock ?? TimeProvider.System; _log = log; }

    private sealed record Cached(StaleDataNotice? Notice);

    public async Task<StaleDataNotice?> CurrentAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue(CacheKey, out Cached? hit) && hit is not null) return hit.Notice;
        StaleDataNotice? notice = null;
        try
        {
            var state = await _published.CurrentAsync(ct);
            if (state.ShownTime is not null)
            {
                var hours = StaleDataWarning.DefaultHours;
                try { hours = StaleDataWarning.HoursFrom((await _settings.ReadSettingsAsync(ct)).Rows); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log?.LogWarning(ex, "the settings could not be read -- the data-getting-old warning uses the default limit"); }
                var now = _clock.GetUtcNow().UtcDateTime;
                if (StaleDataWarning.Evaluate(state, hours, now, null) is not null)
                {
                    FlowRun? last = null;
                    try { last = await _flow.LastPipelineRunAsync(ct); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { _log?.LogWarning(ex, "the newest run record could not be read -- the warning goes without it"); }
                    notice = StaleDataWarning.Evaluate(state, hours, now, last);
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "whether the data is getting old could not be read -- no warning is shown");
            notice = null;
        }
        _cache?.Set(CacheKey, new Cached(notice), Ttl);
        return notice;
    }
}
