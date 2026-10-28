using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Performance;

/// <summary>
/// THE PERFORMANCE PAGE'S RULES (#757) -- all PURE, all tested (PerformanceTests). The runs and steps (the same as the
/// heartbeat's pipeline estimate, engine\_shared\SI-HeartbeatFields.ps1 Get-SIPipelineEta: each step's earlier time is its
/// time in the newest run that went well; the steps of one group run together), the collection state (the same rules as the
/// heartbeat's Collections, engine\_shared\SI-HeartbeatJob.ps1 ConvertTo-SIHeartbeatCollections), stale after 48 hours.
/// </summary>
public static class PerfRules
{
    public const double PacingHighDefault = 85;
    public const int StaleHours = 48;
    public const int StaleRunMinutes = 30;

    /// A step's job as its short key (caj-si-identity -> identity).
    public static string StepKey(string? job)
    {
        var k = (job ?? "").Trim().ToLowerInvariant();
        return k.StartsWith("caj-si-", StringComparison.Ordinal) ? k["caj-si-".Length..] : k;
    }

    public static double? Median(IEnumerable<double> values)
    {
        var v = values.OrderBy(x => x).ToList();
        if (v.Count == 0) return null;
        return v.Count % 2 == 1 ? v[v.Count / 2] : (v[v.Count / 2 - 1] + v[v.Count / 2]) / 2.0;
    }

    /// Each step's time per run (oldest run first, as the trend reads), its typical time (the median of its good runs) and
    /// its last good time. Steps in the order of the newest run, then any other step seen.
    public static IReadOnlyList<PerfStepTrend> StepTrends(IReadOnlyList<PerfRun> runsNewestFirst, IReadOnlyList<PerfStep> steps, Func<string, string> label)
    {
        var order = runsNewestFirst.Reverse().Select(r => r.Id).ToList();
        var newest = runsNewestFirst.FirstOrDefault()?.Id;
        var keys = steps.Where(s => s.RunId == newest).OrderBy(s => s.Order).Select(s => s.Key)
            .Concat(steps.OrderBy(s => s.Order).Select(s => s.Key)).Where(k => k.Length > 0).Distinct().ToList();
        var list = new List<PerfStepTrend>();
        foreach (var k in keys)
        {
            var mine = steps.Where(s => s.Key == k && s.State == "Success" && s.Minutes is not null).ToList();
            var perRun = order.Select(id => mine.FirstOrDefault(s => s.RunId == id)?.Minutes).ToList();
            var job = steps.First(s => s.Key == k).Job;
            list.Add(new PerfStepTrend(k, label(job), perRun, Median(mine.Select(s => s.Minutes!.Value)), perRun.LastOrDefault(m => m is not null)));
        }
        return list;
    }

    /// How long each step took the last time it went well, from the runs other than -exclude: the newest SUCCEEDED run first,
    /// then the others (newest first) -- the heartbeat's rule (Get-SIPipelinePreviousMinutes).
    public static IReadOnlyDictionary<string, double> PreviousMinutes(IReadOnlyList<PerfRun> runs, IReadOnlyList<PerfStep> steps, string? exclude)
    {
        var map = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var r in runs.Where(r => r.Id != exclude).OrderBy(r => r.State == "Succeeded" ? 0 : 1).ThenByDescending(r => r.StartedUtc))
            foreach (var s in steps.Where(s => s.RunId == r.Id && s.State == "Success" && s.Minutes is not null))
                map.TryAdd(s.Key, s.Minutes!.Value);
        return map;
    }

    /// The run in progress (the newest run, when it is Running), or null.
    public static PerfProgress? Progress(IReadOnlyList<PerfRun> runsNewestFirst, IReadOnlyList<PerfStep> steps, DateTime nowUtc, Func<string, string> label)
    {
        var run = runsNewestFirst.FirstOrDefault();
        if (run is null || run.State != "Running") return null;
        var stalled = run.HeartbeatUtc is not { } hb || (nowUtc - hb).TotalMinutes > StaleRunMinutes;
        var mine = steps.Where(s => s.RunId == run.Id && s.State != "Disabled").OrderBy(s => s.Order).ToList();
        static bool Running(PerfStep s) => s.State is "Running" or "Starting";
        var open = mine.Where(s => Running(s) || s.State == "Waiting").ToList();
        var prev = PreviousMinutes(runsNewestFirst, steps, run.Id);
        var cursor = nowUtc; var unknown = false; var overdue = false;
        foreach (var g in open.GroupBy(s => s.Group > 0 ? "g" + s.Group : "s" + s.Order).OrderBy(g => g.Min(s => s.Order)))
        {
            double longest = 0;
            foreach (var s in g)
            {
                if (!prev.TryGetValue(s.Key, out var p)) { unknown = true; continue; }
                var left = Running(s) ? p - (s.StartedUtc is { } st ? Math.Max(0, (nowUtc - st).TotalMinutes) : 0) : p;
                if (left < 0) { overdue = true; continue; }
                longest = Math.Max(longest, left);
            }
            cursor = cursor.AddMinutes(longest);
        }
        var running = mine.Where(Running).Select(s => (label(s.Job), s.StartedUtc)).ToList();
        return new PerfProgress(run, mine.Count - open.Count, mine.Count, running, open.Count > 0 && cursor > nowUtc ? cursor : null,
            overdue ? "overdue" : unknown ? "partial" : "known", stalled);
    }

    // ---- the collection state: the heartbeat's Collections rules, over the same rows ----

    public static readonly IReadOnlyDictionary<string, string> SourceLabels = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["identity"] = "Identity (Entra ID)", ["endpoint"] = "Endpoints (Defender)", ["azure"] = "Azure", ["publicip"] = "Public IP addresses",
        ["riskAnalysisSummary"] = "Risk Analysis Summary", ["riskAnalysisDetailed"] = "Risk Analysis Detailed", ["ciBuild"] = "CI build",
    };

    public static string StateLabel(string state) => state switch
    {
        "complete" => "Complete", "partial" => "Partly collected", "failed" => "Failed", "never" => "Never collected", "running" => "Running now",
        "held" => "Held: last good result kept", _ => state,
    };

    private static string? S(SqlRow? r, string c) => r?.Str(c);
    private static DateTime? T(SqlRow? r, string c) => r?.Date(c) is { } d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : null;
    private static long? N(SqlRow? r, string c) { try { return r?.Long(c); } catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException) { return null; } }
    private static bool Flag(SqlRow? r, string c) => S(r, c) is "1" or "True" or "true";

    /// One entry per source / report SI has a record of -- the heartbeat's states, plus Stale (the last good collection is
    /// older than 48 hours). -runningKeys: the step keys running now (a source whose step runs now is "running").
    /// summaryOn (#636): false = the Risk Analysis Summary step is off -- its row is left out (unless it runs now).
    public static IReadOnlyList<PerfSource> Sources(IReadOnlyList<SqlRow> rows, IReadOnlyCollection<string> runningKeys, DateTime nowUtc, bool summaryOn = true)
    {
        SqlRow? Get(string k, string n) => rows.FirstOrDefault(r => S(r, "K") == k && string.Equals(S(r, "Name"), n, StringComparison.OrdinalIgnoreCase));
        bool Stale(DateTime? good) => good is { } g && (nowUtc - g).TotalHours > StaleHours;
        var list = new List<PerfSource>();
        foreach (var kind in new[] { "identity", "endpoint", "azure", "publicip" })
        {
            var src = Get("source", kind); var rec = Get("records", kind);
            var run = runningKeys.Contains(kind);
            if (src is null && rec is null && !run) continue;
            var good = T(src, "T1"); var att = T(src, "T2");
            var ok = src is null || S(src, "F1") is null || Flag(src, "F1");
            var held = Flag(rec, "F1");
            att ??= T(rec, "T1");
            if (good is null && rec is not null && !held) good = T(rec, "T1");
            var collected = kind == "identity" ? N(rec, "N2") : N(rec, "N1");
            string state; string? note;
            if (run) { state = "running"; note = "collecting now"; }
            else if (src is not null && !ok) { state = "failed"; note = good is not null ? "the newest collection did not end well; the data is from the last complete collection" : "the newest collection did not end well and no complete collection is recorded"; }
            else if (held) { state = "partial"; note = "the newest collection did not reach every record; what it did not reach keeps its last known state"; }
            else if (good is null) { state = "never"; note = "no complete collection is recorded yet"; }
            else { state = "complete"; note = null; }
            list.Add(new PerfSource(kind, SourceLabels[kind], state, good, att, collected, null, note, Stale(good)));
        }
        foreach (var (kind, grain, step) in new[] { ("riskAnalysisSummary", "Summary", "risk-analysis"), ("riskAnalysisDetailed", "Detailed", "risk-analysis-detailed") })
        {
            var ra = Get("ra", grain);
            var run = runningKeys.Contains(step);
            if (ra is null && !run) continue;
            if (grain == "Summary" && !summaryOn && !run) continue;
            var complete = T(ra, "T1"); var att = T(ra, "T2");
            var nc = N(ra, "N3");
            // #902: of the reports not complete, those SI held ON PURPOSE at their last complete result (N4)
            var nh = N(ra, "N4");
            string state; string? note;
            if (run) { state = "running"; note = "Risk Analysis runs now"; }
            else if (complete is null) { state = "never"; note = "no complete Risk Analysis collection yet"; }
            else if (!Flag(ra, "F1")) { state = "failed"; note = "the newest Risk Analysis run did not complete; the last complete collection is shown"; }
            else if (nc > 0 && nh is { } h && h >= nc) { state = "held"; note = $"{h} report(s) of the newest collection held on purpose at their last complete result -- nothing of them is closed"; }
            else if (Flag(ra, "F2") || nc > 0) { state = "partial"; note = nc > 0 ? (nh > 0 ? $"{nc} report(s) of the newest collection are not complete, {nh} of them held on purpose at their last complete result" : $"{nc} report(s) of the newest collection are not complete") : "the newest collection was loaded although part of its run was not complete"; }
            else { state = "complete"; note = null; }
            list.Add(new PerfSource(kind, SourceLabels[kind], state, complete, att, N(ra, "N2"), N(ra, "N1"), note, Stale(complete)));
        }
        var st = Get("ci", "LastBuildStatus"); var start = Get("ci", "LastBuildStart");
        var ciRun = runningKeys.Contains("asset-correlation");
        if (st is not null || ciRun)
        {
            var v = (S(st, "Txt") ?? "").Trim().ToLowerInvariant();
            DateTime? att = DateTime.TryParse(S(start, "Txt"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var a) ? a : null;
            DateTime? done = null; string state; string? note;
            if (ciRun) { state = "running"; note = "the CI build runs now"; }
            else if (v == "running") { state = "failed"; note = "the last CI build was stopped before it finished"; }
            else if (v == "ok") { state = "complete"; note = null; done = T(st, "T1"); }
            else if (v == "partial") { state = "partial"; note = "the last CI build finished, but not every CI reached Log Analytics"; }
            else if (v == "failed") { state = "failed"; note = "the last CI build failed"; }
            else { state = "never"; note = "no CI build is recorded yet"; }
            list.Add(new PerfSource("ciBuild", SourceLabels["ciBuild"], state, done, att, null, null, note, Stale(done)));
        }
        return list;
    }

    /// The step keys running now in the newest run (a run whose runner went quiet runs nothing).
    public static IReadOnlyCollection<string> RunningKeys(PerfProgress? p, IReadOnlyList<PerfStep> steps) =>
        p is null || p.Stalled ? (IReadOnlyCollection<string>)Array.Empty<string>()
        : steps.Where(s => s.RunId == p.Run.Id && s.State is "Running" or "Starting").Select(s => s.Key).ToHashSet(StringComparer.Ordinal);

    /// "1 h 25 min", "45 min", "3 d 4 h" -- plain words.
    public static string Span(TimeSpan? t)
    {
        if (t is not { } x) return "--";
        if (x < TimeSpan.Zero) x = TimeSpan.Zero;
        if (x.TotalMinutes < 1) return "under a minute";
        if (x.TotalHours < 1) return $"{(int)x.TotalMinutes} min";
        if (x.TotalDays < 1) return $"{(int)x.TotalHours} h {x.Minutes} min";
        return $"{(int)x.TotalDays} d {x.Hours} h";
    }

    public static string Minutes(double? m) => m is { } v ? Span(TimeSpan.FromMinutes(v)) : "--";

    public static string RunStateLabel(string state) => state switch
    {
        "Succeeded" => "Succeeded", "Failed" => "Failed", "Running" => "Running", "Stopped" => "Stopped", "Interrupted" => "Interrupted", _ => state,
    };
}

/// One hour of a resource's load in percent of what its size allows (the highest of its parts).
public sealed record PerfLoadHour(DateTime HourUtc, double Avg, double Max);

/// What the page advises for one sized item. Direction: up | down | keep | unknown.
public sealed record PerfAdvice(string Kind, string Name, string Label, string Current, string Direction, string? Suggest, string Text,
    int HoursSampled, int HoursAtLimit, double IdleShare, double? PeakPercent, int HoursAbovePacing);

/// <summary>
/// THE SIZE RECOMMENDATION (owner 2026-10-18: "so they can choose to scale up down"). From the last 7 days of hourly load:
///   * fewer than 24 hours measured -- no advice yet;
///   * at its limit (an hour's highest at or above 95 % -- 90 % for the web app) for 10 hours or more -- the next size up;
///   * idle (an hour's average under 10 %) 95 % of the hours or more, AND the busiest hour would still stay under 90 % one
///     size down -- the next size down (never below S1, never Basic; the web app never below 1 CPU / 2 GiB);
///   * otherwise the size fits.
/// The database's load: its DTU percent where it has one, else the highest of CPU, data IO and log write.
/// </summary>
public static class PerfAdvisor
{
    public const double DbLimit = 95, WebLimit = 90, IdleBelow = 10, IdleShareForDown = 0.95, StayUnderAfterDown = 90;
    public const int MinHours = 24, LimitHoursForUp = 10;

    public static IReadOnlyList<PerfLoadHour> DatabaseLoad(IReadOnlyDictionary<(string Kind, string Name, string Metric), IReadOnlyList<PerfPoint>> s, string name)
    {
        IReadOnlyList<PerfPoint> Of(string m) => s.TryGetValue(("database", name, m), out var p) ? p : [];
        var dtu = Of("dtu_consumption_percent");
        if (dtu.Count > 0) return dtu.Select(p => new PerfLoadHour(p.HourUtc, p.Avg ?? p.Max ?? 0, p.Max ?? p.Avg ?? 0)).ToList();
        var parts = new[] { Of("cpu_percent"), Of("physical_data_read_percent"), Of("log_write_percent") };
        return parts.SelectMany(x => x).GroupBy(p => p.HourUtc).OrderBy(g => g.Key)
            .Select(g => new PerfLoadHour(g.Key, g.Max(p => p.Avg ?? p.Max ?? 0), g.Max(p => p.Max ?? p.Avg ?? 0))).ToList();
    }

    /// The web app's load: CPU in percent of its CPUs and memory in percent of its memory, the higher of the two per hour.
    public static IReadOnlyList<PerfLoadHour> WebLoad(IReadOnlyDictionary<(string Kind, string Name, string Metric), IReadOnlyList<PerfPoint>> s, string name, double? cpu, double? memGi)
    {
        if (cpu is not > 0 || memGi is not > 0) return [];
        IReadOnlyList<PerfPoint> Of(string m) => s.TryGetValue(("webapp", name, m), out var p) ? p : [];
        var c = Of("UsageNanoCores").ToDictionary(p => p.HourUtc);
        var m = Of("WorkingSetBytes").ToDictionary(p => p.HourUtc);
        double Cpu(double? v) => (v ?? 0) / 1e9 / cpu.Value * 100;
        double Mem(double? v) => (v ?? 0) / (memGi.Value * 1073741824.0) * 100;
        return c.Keys.Union(m.Keys).OrderBy(h => h).Select(h =>
        {
            c.TryGetValue(h, out var cp); m.TryGetValue(h, out var mp);
            return new PerfLoadHour(h, Math.Max(Cpu(cp?.Avg ?? cp?.Max), Mem(mp?.Avg ?? mp?.Max)), Math.Max(Cpu(cp?.Max ?? cp?.Avg), Mem(mp?.Max ?? mp?.Avg)));
        }).ToList();
    }

    public static string Pct(double v) => v.ToString("N0", SI.Management.Core.ProData.ScoreFormat.Culture) + " %";

    private static (int Sampled, int AtLimit, double Idle, double? Peak, int AbovePacing) Measure(IReadOnlyList<PerfLoadHour> load, double limit, double pacing) =>
        (load.Count, load.Count(h => h.Max >= limit), load.Count == 0 ? 0 : load.Count(h => h.Avg < IdleBelow) / (double)load.Count,
         load.Count == 0 ? null : load.Max(h => h.Max), load.Count(h => h.Max >= pacing));

    public static PerfAdvice Database(string name, string label, string? current, IReadOnlyList<PerfLoadHour> load, double pacingHigh)
    {
        var (n, lim, idle, peak, pace) = Measure(load, DbLimit, pacingHigh);
        var cur = (current ?? "").Trim();
        PerfAdvice A(string dir, string? sug, string text) => new("database", name, label, cur.Length > 0 ? cur : "not known", dir, sug, text, n, lim, idle, peak, pace);
        if (n < MinHours) return A("unknown", null, "Not enough measurements yet. The load is recorded every hour; the advice comes after the first day.");
        var i = PerfSizing.SqlIndex(cur);
        if (i < 0)
            return A("keep", null, cur.Length == 0
                ? $"The size this database runs is not known here. It was at its limit for {lim} hours this week."
                : $"This database runs {cur}, a size this page does not change. It was at its limit for {lim} hours this week, busy at most {Pct(peak ?? 0)}.");
        if (lim >= LimitHoursForUp)
            return i + 1 < PerfSizing.SqlLadder.Count
                ? A("up", PerfSizing.SqlLadder[i + 1], $"The database was at its limit for {lim} hours this week -- a larger size ({PerfSizing.SqlLadder[i + 1]}) would shorten the nightly run.")
                : A("keep", null, $"The database was at its limit for {lim} hours this week. It already runs the largest size offered here.");
        if (idle >= IdleShareForDown && i > 0)
        {
            var down = PerfSizing.SqlLadder[i - 1];
            var projected = (peak ?? 0) * PerfSizing.SqlDtu[cur] / PerfSizing.SqlDtu[down];
            if (projected < StayUnderAfterDown)
                return A("down", down, $"The database is idle {Pct(idle * 100)} of the week -- {down} would be enough.");
        }
        return A("keep", null, $"The size fits: the database was busy at most {Pct(peak ?? 0)} and at its limit for {lim} hours this week.");
    }

    public static PerfAdvice WebApp(string name, double? cpu, double? memGi, IReadOnlyList<PerfLoadHour> load)
    {
        var (n, lim, idle, peak, _) = Measure(load, WebLimit, 101);
        var cur = cpu is { } c && memGi is { } m ? PerfSizing.WebText(c, m) : "not known";
        PerfAdvice A(string dir, string? sug, string text) => new("webapp", name, "Web app", cur, dir, sug, text, n, lim, idle, peak, 0);
        if (cpu is null || memGi is null) return A("unknown", null, "The web app's size is not known here yet. The status job reads it every hour.");
        if (n < MinHours) return A("unknown", null, "Not enough measurements yet. The load is recorded every hour; the advice comes after the first day.");
        var i = PerfSizing.WebIndex(cpu.Value, memGi.Value);
        if (lim >= LimitHoursForUp)
        {
            var next = PerfSizing.WebLadder.FirstOrDefault(o => o.Cpu > cpu.Value);
            return next.Cpu > 0
                ? A("up", PerfSizing.WebText(next.Cpu, next.MemoryGi), $"The web app was at its limit for {lim} hours this week -- {PerfSizing.WebText(next.Cpu, next.MemoryGi)} would keep the pages quick.")
                : A("keep", null, $"The web app was at its limit for {lim} hours this week. It already runs the largest size offered here.");
        }
        if (idle >= IdleShareForDown && i > 0)
        {
            var down = PerfSizing.WebLadder[i - 1];
            var projected = (peak ?? 0) * cpu.Value / down.Cpu;
            if (projected < StayUnderAfterDown)
                return A("down", PerfSizing.WebText(down.Cpu, down.MemoryGi), $"The web app is idle {Pct(idle * 100)} of the week -- {PerfSizing.WebText(down.Cpu, down.MemoryGi)} would be enough.");
        }
        return A("keep", null, $"The size fits: the web app was busy at most {Pct(peak ?? 0)} and at its limit for {lim} hours this week.");
    }
}

/// <summary>
/// THE SIZES AN ADMIN MAY ASK FOR HERE, and the customer's settings they are kept in (the updater applies them, up AND down
/// -- the web app has no right to change Azure, CR8). The setting names are the ones the updater reads (the same three as
/// the right-size work, branch si-v3-scale/right-size: text settings, "S4" / "1.5" / "3Gi"); the control is offered only
/// while the shipped settings catalog knows the setting.
/// Never below S1, never Basic; the web app at least 1 CPU / 2 GiB.
/// </summary>
public static class PerfSizing
{
    public const string SqlKey = "SI_Bootstrap_SqlServiceObjective";
    public const string WebCpuKey = "SI_Bootstrap_WebAppCpu";
    public const string WebMemoryKey = "SI_Bootstrap_WebAppMemory";

    public static readonly IReadOnlyList<string> SqlLadder = ["S1", "S2", "S3", "S4", "S6", "S7", "S9", "S12"];
    public static readonly IReadOnlyDictionary<string, int> SqlDtu = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
    {
        ["S1"] = 20, ["S2"] = 50, ["S3"] = 100, ["S4"] = 200, ["S6"] = 400, ["S7"] = 800, ["S9"] = 1600, ["S12"] = 3000,
    };
    public static readonly IReadOnlyList<(double Cpu, double MemoryGi)> WebLadder = [(1, 2), (1.5, 3), (2, 4), (3, 6), (4, 8)];

    public static int SqlIndex(string? so) => SqlLadder.ToList().FindIndex(s => string.Equals(s, (so ?? "").Trim(), StringComparison.OrdinalIgnoreCase));
    public static int WebIndex(double cpu, double mem) => WebLadder.ToList().FindIndex(o => Math.Abs(o.Cpu - cpu) < 0.01 && Math.Abs(o.MemoryGi - mem) < 0.01);

    public static string WebText(double cpu, double memGi) =>
        cpu.ToString("0.##", SI.Management.Core.ProData.ScoreFormat.Culture) + " CPU / " + memGi.ToString("0.##", SI.Management.Core.ProData.ScoreFormat.Culture) + " GiB";

    /// Why a database size cannot be asked for, or null.
    public static string? ValidateSql(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) return "Choose a size.";
        if (v.Equals("Basic", StringComparison.OrdinalIgnoreCase) || v.Equals("S0", StringComparison.OrdinalIgnoreCase)) return "Basic and S0 are too small for SecurityInsight -- S1 is the smallest size.";
        return SqlIndex(v) < 0 ? $"{v} is not one of the sizes offered here ({string.Join(", ", SqlLadder)})." : null;
    }

    /// The web app option "1.5|3" -> (1.5, 3), or the reason it cannot be asked for.
    public static ((double Cpu, double MemoryGi)? Option, string? Refusal) ParseWeb(string? value)
    {
        var p = (value ?? "").Split('|');
        if (p.Length != 2 || !double.TryParse(p[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var c) || !double.TryParse(p[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var m))
            return (null, "Choose a size.");
        if (c < 1 || m < 2) return (null, "The web app needs at least 1 CPU / 2 GiB.");
        return WebIndex(c, m) < 0 ? (null, "That is not one of the sizes offered here.") : ((c, m), null);
    }

    public static string WebValue(double cpu, double mem) => cpu.ToString("0.##", CultureInfo.InvariantCulture) + "|" + mem.ToString("0.##", CultureInfo.InvariantCulture);

    /// A stored setting value without its JSON quotes.
    public static string Unquote(string? json)
    {
        var t = (json ?? "").Trim();
        if (t.Length == 0 || t == "null") return "";
        if (t.StartsWith('"'))
            try { return JsonSerializer.Deserialize<string>(t) ?? ""; } catch (JsonException) { return t.Trim('"'); }
        return t;
    }

    /// The value as the catalog's type wants it: a number for a numeric setting, else text.
    public static JsonElement Json(string? catalogType, double number, string text) =>
        catalogType is "int" or "integer" or "number" or "decimal" or "double" or "float"
            ? JsonSerializer.SerializeToElement(number)
            : JsonSerializer.SerializeToElement(text);

    /// The memory as the setting keeps it when it is text ("3Gi"), the way Container Apps writes it.
    public static string MemoryText(double gi) => gi.ToString("0.##", CultureInfo.InvariantCulture) + "Gi";

    /// Parse a stored web value (number or "3Gi") back to GiB.
    public static double? ParseGi(string? v)
    {
        var t = (v ?? "").Trim();
        if (t.EndsWith("Gi", StringComparison.OrdinalIgnoreCase)) t = t[..^2];
        return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var x) ? x : null;
    }

    /// Requested -> applied: has the size asked for become the size the resource runs?
    public static bool SqlApplied(string? requested, string? running) =>
        !string.IsNullOrWhiteSpace(requested) && string.Equals(requested.Trim(), (running ?? "").Trim(), StringComparison.OrdinalIgnoreCase);

    public static bool WebApplied(double? reqCpu, double? reqMem, double? cpu, double? mem) =>
        reqCpu is { } rc && reqMem is { } rm && cpu is { } c && mem is { } m && Math.Abs(rc - c) < 0.01 && Math.Abs(rm - m) < 0.01;
}

/// <summary>
/// The approximate monthly list prices of the sizes offered (a small catalog shipped with the app, Performance\size-prices.json,
/// with the date it was taken). Approximate, before discounts -- the page says so.
/// </summary>
public sealed class PerfPrices
{
    public string AsOf { get; init; } = "";
    public string Currency { get; init; } = "USD";
    public string Note { get; init; } = "";
    public IReadOnlyDictionary<string, double> Database { get; init; } = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
    public double WebPerCpuMonth { get; init; }
    public double WebPerGiBMonth { get; init; }

    public double? Sql(string? so) => so is not null && Database.TryGetValue(so.Trim(), out var p) ? p : null;
    public double Web(double cpu, double memGi) => cpu * WebPerCpuMonth + memGi * WebPerGiBMonth;
    public string Money(double? v) => v is { } x ? "about " + Currency + " " + x.ToString("N0", SI.Management.Core.ProData.ScoreFormat.Culture) + " a month" : "price not known";

    public static readonly PerfPrices None = new();

    private static PerfPrices? _shipped;

    /// The catalog embedded in the app (read once); an unreadable catalog = no prices, never an error page.
    public static PerfPrices Shipped()
    {
        if (_shipped is not null) return _shipped;
        try
        {
            using var s = typeof(PerfPrices).Assembly.GetManifestResourceStream("Performance/size-prices.json");
            _shipped = s is null ? None : Parse(s);
        }
        catch (Exception ex) when (ex is JsonException or IOException or InvalidOperationException) { _shipped = None; }
        return _shipped;
    }

    public static PerfPrices Parse(Stream json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var db = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        if (r.TryGetProperty("database", out var d) && d.ValueKind == JsonValueKind.Object)
            foreach (var p in d.EnumerateObject()) if (p.Value.ValueKind == JsonValueKind.Number) db[p.Name] = p.Value.GetDouble();
        double Num(string n) => r.TryGetProperty("webapp", out var w) && w.TryGetProperty(n, out var x) && x.ValueKind == JsonValueKind.Number ? x.GetDouble() : 0;
        string Str(string n) => r.TryGetProperty(n, out var x) && x.ValueKind == JsonValueKind.String ? x.GetString() ?? "" : "";
        return new PerfPrices { AsOf = Str("asOf"), Currency = Str("currency") is { Length: > 0 } c ? c : "USD", Note = Str("note"), Database = db,
            WebPerCpuMonth = Num("perCpuMonth"), WebPerGiBMonth = Num("perGiBMonth") };
    }
}
