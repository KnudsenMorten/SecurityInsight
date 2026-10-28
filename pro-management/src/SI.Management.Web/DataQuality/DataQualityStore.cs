using System.Globalization;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;

namespace SI.Management.Web.DataQuality;

/// One fingerprinted pipeline run (sidata.DataQualityRun): the Risk Analysis Detailed collection it measured, how many key
/// numbers, how many were off their expected range, whether it was still learning (fewer than 3 earlier runs), and the
/// daily mail. Times are UTC.
public sealed record DataQualityRun(string RunId, DateTime? CollectionTime, DateTime ComputedAt, int Metrics, int Anomalies, bool Learning,
    int? EarlierRuns, double? LargestDeltaPct, DateTime? MailedAt, string? MailState);

/// One key number off the median of the last 3 runs (sidata.DataQualityAnomaly). Earlier1 is the newest earlier run.
public sealed record DataQualityAnomaly(string MetricKey, string Kind, string Label, string Direction, string Rule,
    double? Earlier1, double? Earlier2, double? Earlier3, double? Expected, double Now, double? ChangePct, string? Cause, string? Step)
{
    /// The three earlier values, oldest first (as the mail shows them).
    public IEnumerable<double?> EarlierOldestFirst => new[] { Earlier3, Earlier2, Earlier1 };

    /// The rule of ONE warning for the fields of one source that are filled less in one run (the fields are listed inside it).
    public const string SourceRule = "source-fill-drop";

    /// Whether this is the one-per-source warning.
    public bool IsSource => string.Equals(Rule, SourceRule, StringComparison.OrdinalIgnoreCase);

    /// The rule of the CLASSIFICATION INCOMPLETE warning (owner 2026-10-19: "goal is to put everything in tier 0-3 and not
    /// have anything unclassified"): findings without a risk rating / tier / asset, active CIs without a tier -- any count
    /// above 0, from the first run on; its groups (report / asset type) and their cause are listed inside it.
    public const string ClassificationRule = "classification-incomplete";

    /// Whether this is a classification-incomplete warning.
    public bool IsClassification => string.Equals(Rule, ClassificationRule, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// One field inside a one-per-source warning (sidata.DataQualityAnomalyField): the field's key number, its 3 earlier
/// values (Earlier1 = the newest), the expected value, now and the change in points.
/// </summary>
public sealed record DataQualityAnomalyField(string FieldKey, string Label, double? Earlier1, double? Earlier2, double? Earlier3, double? Expected, double Now, double? ChangePct)
{
    /// The field's own name: what follows "fill.src.&lt;source&gt;." in its key (the label when the key is not of that form).
    public string Name
    {
        get
        {
            const string prefix = "fill.src.";
            if (!FieldKey.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return Label;
            var dot = FieldKey.IndexOf('.', prefix.Length);
            return dot > 0 && dot < FieldKey.Length - 1 ? FieldKey[(dot + 1)..] : Label;
        }
    }
}

/// One key number of a run (sidata.DataQualityMetric): a count, or a fill in percent.
public sealed record DataQualityMetric(string MetricKey, string Kind, string Label, double Value, string? Step);

/// One settings change of a run's window (sidata.DataQualityChange, copied from the change log by the data sync).
public sealed record DataQualityChange(long ChangeId, string Name, string? Scope, string? Kind, string? Action, DateTime ChangedAt, string? ChangedBy);

/// One run's value of every key number it measured -- a point of each number's trend.
public sealed record DataQualityTrendRun(string RunId, DateTime ComputedAt, IReadOnlyDictionary<string, double> Values);

/// <summary>
/// Everything of ONE run the panel shows beyond its row: its anomalies (most significant first), its key numbers, the
/// same numbers in the runs before it (oldest first, ending with the run itself when it has numbers), the settings changes
/// of its window and which of them concern which number. <see cref="HasCauseRows"/>: the database has the two cause tables
/// (else a warning's likely cause is its stored text only).
/// </summary>
public sealed record DataQualityDetail(IReadOnlyList<DataQualityAnomaly> Anomalies, IReadOnlyList<DataQualityMetric> Metrics,
    IReadOnlyList<DataQualityTrendRun> Trend, bool HasCauseRows, IReadOnlyList<DataQualityChange> Changes, IReadOnlyDictionary<string, IReadOnlyList<long>> CauseOf)
{
    public static readonly DataQualityDetail Empty = new(Array.Empty<DataQualityAnomaly>(), Array.Empty<DataQualityMetric>(), Array.Empty<DataQualityTrendRun>(),
        false, Array.Empty<DataQualityChange>(), new Dictionary<string, IReadOnlyList<long>>());

    /// The fields inside each one-per-source warning, by the warning's key (largest drop first). A warning that is not
    /// one-per-source has no entry; neither has one in a database without the table of fields.
    public IReadOnlyDictionary<string, IReadOnlyList<DataQualityAnomalyField>> Fields { get; init; } =
        new Dictionary<string, IReadOnlyList<DataQualityAnomalyField>>(StringComparer.OrdinalIgnoreCase);

    /// The fields inside one warning (none for a warning that is about one key number).
    public IReadOnlyList<DataQualityAnomalyField> FieldsOf(DataQualityAnomaly a) =>
        Fields.TryGetValue(a.MetricKey, out var list) ? list : Array.Empty<DataQualityAnomalyField>();

    /// How many key numbers the warnings stand for: a one-per-source warning counts its fields.
    public int NumbersOutside => Anomalies.Sum(a => Math.Max(1, FieldsOf(a).Count));
}

/// <summary>
/// What the Data quality panel shows: the tables exist, the newest run, the run that is looked at (the newest, or the one
/// picked from the history), the recent runs (newest first) and the picked run's detail. <see cref="SelectedMissing"/>:
/// a run was asked for that is not in the database.
/// </summary>
public sealed record DataQualityView(bool HasTables, DataQualityRun? Latest, DataQualityRun? Selected, bool SelectedMissing,
    IReadOnlyList<DataQualityRun> Recent, DataQualityDetail Detail)
{
    public static readonly DataQualityView Missing = new(false, null, null, false, Array.Empty<DataQualityRun>(), DataQualityDetail.Empty);

    /// For a picked run that sent no mail because its warnings were the same as the last mail's: the run that mail was
    /// about (the newest mailed run before it). Null for every other run, and when that run is gone.
    public DataQualityRun? MailOf { get; init; }
}

/// Whether a run's data-quality mail went out and, if not, why (sidata.DataQualityRun.MailState, written by the data sync).
public static class DataQualityMail
{
    public const string Sent = "sent";
    public const string Failed = "failed";
    /// The warnings were the same as the last mail's: the mail goes out only when they change.
    public const string Unchanged = "unchanged";
    /// A data-quality mail went out earlier the same day (at most one a day).
    public const string DayLimit = "day-limit";
    public const string Off = "off";
    public const string NoRecipients = "no-recipients";
}

/// <summary>
/// THE DATA-QUALITY WARNINGS (REQUIREMENTS #577 step 2). The data sync's last step (engine\pro-data\_shared\SI-DataQuality.ps1)
/// writes one fingerprint per pipeline run and the key numbers off the median of the last 3 runs; the web app only READS
/// them. Never a guard: nothing here holds, releases or blocks anything.
/// </summary>
public interface IDataQualityStore
{
    /// <param name="runId">The run to look at (null / empty = the newest).</param>
    /// <param name="recentRuns">How many runs the history lists.</param>
    /// <param name="trendRuns">How many runs each number's trend covers (the picked run and the ones before it).</param>
    Task<DataQualityView> ReadAsync(string? runId, int recentRuns, int trendRuns, CancellationToken ct);
}

/// <summary>
/// Reads the prepared rows by key -- the run list (an index end), then the picked run's rows by its RunId (primary keys);
/// no document, no JSON. A run's rows never change once the data sync wrote them, so the picked run's detail is kept per
/// data version (<see cref="ViewResultCache"/>) and only while it is complete (as many numbers and anomalies as the run
/// row says). Every statement is read-only (<see cref="SqlGuard"/>) and parameterised.
/// </summary>
public sealed class SqlDataQualityStore : IDataQualityStore
{
    private readonly ISqlExecutor _sql;
    private readonly ViewResultCache? _cache;
    public SqlDataQualityStore(ISqlExecutor sql, ViewResultCache? cache = null) { _sql = sql; _cache = cache; }

    public const string ProbeSql = """
SELECT CASE WHEN OBJECT_ID(N'sidata.DataQualityRun') IS NOT NULL AND OBJECT_ID(N'sidata.DataQualityAnomaly') IS NOT NULL THEN 1 ELSE 0 END AS HasDataQuality,
       CASE WHEN OBJECT_ID(N'sidata.DataQualityMetric') IS NOT NULL THEN 1 ELSE 0 END AS HasMetrics,
       CASE WHEN OBJECT_ID(N'sidata.DataQualityChange') IS NOT NULL AND OBJECT_ID(N'sidata.DataQualityCause') IS NOT NULL THEN 1 ELSE 0 END AS HasCause,
       CASE WHEN OBJECT_ID(N'sidata.DataQualityAnomalyField') IS NOT NULL THEN 1 ELSE 0 END AS HasFields
""";

    private const string RunColumns = "RunId, CollectionTime, ComputedAt, Metrics, Anomalies, CAST(Learning AS int) AS Learning, EarlierRuns, LargestDeltaPct, MailedAt, MailState";

    /// The newest runs, newest first.
    public const string RunsSql = $"""
SELECT TOP (@Top) {RunColumns}
FROM sidata.DataQualityRun ORDER BY ComputedAt DESC, RunId DESC;
""";

    /// One run by its id (a run picked from an older part of the history than the page lists).
    public const string RunSql = $"""
SELECT {RunColumns}
FROM sidata.DataQualityRun WHERE RunId = @RunId;
""";

    /// The anomalies of one run, most significant first.
    public const string AnomaliesSql = """
SELECT MetricKey, Kind, Label, Direction, [Rule], Earlier1, Earlier2, Earlier3, Expected, NowValue, ChangePct, Cause, Step
FROM sidata.DataQualityAnomaly WHERE RunId = @RunId ORDER BY ABS(ISNULL(ChangePct, 0)) DESC, MetricKey;
""";

    /// The key numbers of one run.
    public const string MetricsSql = """
SELECT MetricKey, Kind, Label, Value, Step
FROM sidata.DataQualityMetric WHERE RunId = @RunId ORDER BY MetricKey;
""";

    /// The key numbers of the picked run and of the runs before it (the trend), oldest run first.
    public const string TrendSql = """
SELECT r.RunId, r.ComputedAt, m.MetricKey, m.Value
FROM (SELECT TOP (@Runs) x.RunId, x.ComputedAt FROM sidata.DataQualityRun AS x
      WHERE x.ComputedAt <= (SELECT s.ComputedAt FROM sidata.DataQualityRun AS s WHERE s.RunId = @RunId)
      ORDER BY x.ComputedAt DESC, x.RunId DESC) AS r
JOIN sidata.DataQualityMetric AS m ON m.RunId = r.RunId
ORDER BY r.ComputedAt, r.RunId;
""";

    /// The settings changes of one run's window, newest first.
    public const string ChangesSql = """
SELECT ChangeId, Name, Scope, Kind, Action, ChangedAt, ChangedBy
FROM sidata.DataQualityChange WHERE RunId = @RunId ORDER BY ChangedAt DESC, ChangeId DESC;
""";

    /// Which change concerns which key number of one run.
    public const string CausesSql = """
SELECT MetricKey, ChangeId
FROM sidata.DataQualityCause WHERE RunId = @RunId;
""";

    /// The fields inside the one-per-source warnings of one run, largest drop first.
    public const string FieldsSql = """
SELECT MetricKey, FieldKey, Label, Earlier1, Earlier2, Earlier3, Expected, NowValue, ChangePct
FROM sidata.DataQualityAnomalyField WHERE RunId = @RunId ORDER BY MetricKey, ABS(ISNULL(ChangePct, 0)) DESC, FieldKey;
""";

    /// The newest run a data-quality mail went out for before a moment (the mail a run with the same warnings refers to).
    public const string MailOfSql = $"""
SELECT TOP (1) {RunColumns}
FROM sidata.DataQualityRun WHERE MailState = N'sent' AND ComputedAt < @Before ORDER BY ComputedAt DESC, RunId DESC;
""";

    /// Every statement of the store (the tests hold each to read-only).
    public static readonly IReadOnlyList<string> Statements = [ProbeSql, RunsSql, RunSql, AnomaliesSql, MetricsSql, TrendSql, ChangesSql, CausesSql, FieldsSql, MailOfSql];

    public static double? Num(SqlRow r, string col) =>
        r.TryGetValue(col, out var v) && v is not null && v is not DBNull ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;

    public static DataQualityRun ToRun(SqlRow r) => new(
        r.Str("RunId") ?? "", r.Date("CollectionTime"), r.Date("ComputedAt") ?? DateTime.MinValue, (int)(r.Long("Metrics") ?? 0), (int)(r.Long("Anomalies") ?? 0),
        (r.Long("Learning") ?? 0) == 1, r.Long("EarlierRuns") is { } e ? (int)e : null, Num(r, "LargestDeltaPct"), r.Date("MailedAt"), r.Str("MailState"));

    public static DataQualityAnomaly ToAnomaly(SqlRow r) => new(
        r.Str("MetricKey") ?? "", r.Str("Kind") ?? "", r.Str("Label") ?? r.Str("MetricKey") ?? "", r.Str("Direction") ?? "", r.Str("Rule") ?? "",
        Num(r, "Earlier1"), Num(r, "Earlier2"), Num(r, "Earlier3"), Num(r, "Expected"), Num(r, "NowValue") ?? 0, Num(r, "ChangePct"), r.Str("Cause"), r.Str("Step"));

    public static DataQualityAnomalyField ToField(SqlRow r) => new(
        r.Str("FieldKey") ?? "", r.Str("Label") ?? r.Str("FieldKey") ?? "", Num(r, "Earlier1"), Num(r, "Earlier2"), Num(r, "Earlier3"), Num(r, "Expected"), Num(r, "NowValue") ?? 0, Num(r, "ChangePct"));

    public static DataQualityMetric ToMetric(SqlRow r) => new(
        r.Str("MetricKey") ?? "", r.Str("Kind") ?? "", r.Str("Label") ?? r.Str("MetricKey") ?? "", Num(r, "Value") ?? 0, r.Str("Step"));

    public static DataQualityChange ToChange(SqlRow r) => new(
        r.Long("ChangeId") ?? 0, r.Str("Name") ?? "", r.Str("Scope"), r.Str("Kind"), r.Str("Action"), r.Date("ChangedAt") ?? DateTime.MinValue, r.Str("ChangedBy"));

    private Task<IReadOnlyList<SqlRow>> Read(string sql, Dictionary<string, object?> p, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(sql);
        return _sql.QueryAsync(sql, p, ct);
    }

    private static Dictionary<string, object?> ById(string runId) => new() { ["RunId"] = runId };

    public async Task<DataQualityView> ReadAsync(string? runId, int recentRuns, int trendRuns, CancellationToken ct)
    {
        var probe = (await Read(ProbeSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
        if ((probe?.Long("HasDataQuality") ?? 0) != 1) return DataQualityView.Missing;
        var hasMetrics = (probe?.Long("HasMetrics") ?? 0) == 1;
        var hasCause = (probe?.Long("HasCause") ?? 0) == 1;
        var hasFields = (probe?.Long("HasFields") ?? 0) == 1;

        var runs = (await Read(RunsSql, new Dictionary<string, object?> { ["Top"] = Math.Max(1, recentRuns) }, ct)).Select(ToRun).ToList();
        var latest = runs.FirstOrDefault();
        var selected = latest;
        var missing = false;
        if (!string.IsNullOrWhiteSpace(runId))
        {
            var id = runId.Trim();
            selected = runs.FirstOrDefault(r => string.Equals(r.RunId, id, StringComparison.OrdinalIgnoreCase))
                       ?? (await Read(RunSql, ById(id), ct)).Select(ToRun).FirstOrDefault();
            missing = selected is null;
        }
        if (selected is null) return new DataQualityView(true, latest, null, missing, runs, DataQualityDetail.Empty);

        DataQualityRun run = selected;
        var points = Math.Max(1, trendRuns);
        Func<Task<DataQualityDetail>> read = () => ReadDetailAsync(run, points, hasMetrics, hasCause, hasFields, ct);
        // complete = as many numbers and anomalies as the run row says (the data sync writes the run row first)
        var detail = _cache is null
            ? await read()
            : await _cache.GetAsync<DataQualityDetail>("dataquality.run|" + run.RunId + "|" + points.ToString(CultureInfo.InvariantCulture) + "|" + (hasCause ? "c" : "t") + (hasFields ? "f" : ""), read, ct,
                d => d.Metrics.Count == run.Metrics && d.Anomalies.Count == run.Anomalies);
        // a run that sent no mail because nothing changed: which mail still stands (the newest mailed run before it)
        DataQualityRun? mailOf = null;
        if (string.Equals(run.MailState, DataQualityMail.Unchanged, StringComparison.OrdinalIgnoreCase))
            mailOf = runs.Where(r => string.Equals(r.MailState, DataQualityMail.Sent, StringComparison.OrdinalIgnoreCase) && r.ComputedAt < run.ComputedAt)
                         .OrderByDescending(r => r.ComputedAt).FirstOrDefault()
                     ?? (await Read(MailOfSql, new Dictionary<string, object?> { ["Before"] = run.ComputedAt }, ct)).Select(ToRun).FirstOrDefault();
        return new DataQualityView(true, latest, run, false, runs, detail) { MailOf = mailOf };
    }

    private async Task<DataQualityDetail> ReadDetailAsync(DataQualityRun run, int trendRuns, bool hasMetrics, bool hasCause, bool hasFields, CancellationToken ct)
    {
        IReadOnlyList<DataQualityAnomaly> anomalies = run.Anomalies > 0
            ? (await Read(AnomaliesSql, ById(run.RunId), ct)).Select(ToAnomaly).ToList()
            : Array.Empty<DataQualityAnomaly>();

        IReadOnlyList<DataQualityMetric> metrics = Array.Empty<DataQualityMetric>();
        var trend = new List<DataQualityTrendRun>();
        if (hasMetrics)
        {
            metrics = (await Read(MetricsSql, ById(run.RunId), ct)).Select(ToMetric).ToList();
            Dictionary<string, double>? values = null;
            string? current = null;
            foreach (var r in await Read(TrendSql, new Dictionary<string, object?> { ["RunId"] = run.RunId, ["Runs"] = trendRuns }, ct))
            {
                var id = r.Str("RunId") ?? "";
                if (values is null || !string.Equals(id, current, StringComparison.Ordinal))
                {
                    values = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
                    current = id;
                    trend.Add(new DataQualityTrendRun(id, r.Date("ComputedAt") ?? DateTime.MinValue, values));
                }
                if (r.Str("MetricKey") is { Length: > 0 } key && Num(r, "Value") is { } v) values[key] = v;
            }
        }

        IReadOnlyList<DataQualityChange> changes = Array.Empty<DataQualityChange>();
        var causeOf = new Dictionary<string, IReadOnlyList<long>>(StringComparer.OrdinalIgnoreCase);
        if (hasCause && anomalies.Count > 0)
        {
            changes = (await Read(ChangesSql, ById(run.RunId), ct)).Select(ToChange).ToList();
            if (changes.Count > 0)
            {
                foreach (var g in (await Read(CausesSql, ById(run.RunId), ct)).GroupBy(r => r.Str("MetricKey") ?? "", StringComparer.OrdinalIgnoreCase))
                    causeOf[g.Key] = g.Select(r => r.Long("ChangeId") ?? 0).Distinct().ToList();
            }
        }

        // the fields inside the one-per-source warnings (read only when the run has such a warning)
        var fields = new Dictionary<string, IReadOnlyList<DataQualityAnomalyField>>(StringComparer.OrdinalIgnoreCase);
        if (hasFields && anomalies.Any(a => a.IsSource || a.IsClassification))
        {
            foreach (var g in (await Read(FieldsSql, ById(run.RunId), ct)).GroupBy(r => r.Str("MetricKey") ?? "", StringComparer.OrdinalIgnoreCase))
                fields[g.Key] = g.Select(ToField).ToList();
        }
        return new DataQualityDetail(anomalies, metrics, trend, hasCause, changes, causeOf) { Fields = fields };
    }
}

/// <summary>
/// One key number of the picked run as the panel lists it: its group, its value now, the values of the (up to) 3 runs
/// before it (oldest first), the expected value (their median -- only with all 3), the change in the rule's own measure,
/// whether it is outside its range, and its trend over the runs before (null = that run did not measure it).
/// </summary>
public sealed record DataQualityNumber(string MetricKey, string Group, string Kind, string Label, double Now, IReadOnlyList<double> Earlier,
    double? Expected, double? Change, string Status, string? Rule, IReadOnlyList<double?> Trend, string? Step)
{
    public const string Outside = "outside";
    public const string Within = "within";
    public const string Learning = "learning";
}

/// The arithmetic of the panel -- the same rules as the data sync's step (median of the last 3 runs; the change per kind).
public static class DataQualityMath
{
    /// How many earlier runs a number is compared with.
    public const int Runs = 3;

    public static double? Median(IEnumerable<double> values)
    {
        var v = values.OrderBy(x => x).ToList();
        if (v.Count == 0) return null;
        var mid = v.Count / 2;
        return v.Count % 2 == 1 ? v[mid] : (v[mid - 1] + v[mid]) / 2.0;
    }

    /// The change of a number against its expected value, in the measure its rule uses: percent of the expected value
    /// (assets, rows), points (a fill), percent of all active CIs (a tier, CIs to retire, an asset class).
    public static double? Change(string kind, double now, double expected, double activeBase) => kind switch
    {
        "fill" => now - expected,
        "tier" or "retire" or "class" => activeBase > 0 ? 100.0 * (now - expected) / activeBase : null,
        _ => expected > 0 ? 100.0 * (now - expected) / expected : null,
    };

    /// The key numbers of the picked run, each with its earlier values, expected value, change, status and trend.
    public static IReadOnlyList<DataQualityNumber> Numbers(DataQualityRun run, DataQualityDetail d)
    {
        var trend = d.Trend;
        var at = -1;
        for (var i = 0; i < trend.Count; i++) if (string.Equals(trend[i].RunId, run.RunId, StringComparison.OrdinalIgnoreCase)) at = i;
        var before = at < 0 ? trend.ToList() : trend.Take(at).ToList();
        var last = before.Skip(Math.Max(0, before.Count - Runs)).ToList();
        var compared = last.Count == Runs;
        var now = d.Metrics.GroupBy(m => m.MetricKey, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
        var activeNow = now.TryGetValue("ci.active", out var an) ? an : 0;
        var activeMedian = Median(last.Where(r => r.Values.ContainsKey("ci.active")).Select(r => r.Values["ci.active"])) ?? 0;
        var activeBase = Math.Max(activeNow, activeMedian);
        var off = d.Anomalies.GroupBy(a => a.MetricKey, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        // a field inside a one-per-source warning is a key number outside its range like any other (only the WARNING is one)
        var offField = d.Fields.Values.SelectMany(x => x).GroupBy(f => f.FieldKey, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var list = new List<DataQualityNumber>(d.Metrics.Count);
        foreach (var m in d.Metrics)
        {
            var points = before.Select(r => r.Values.TryGetValue(m.MetricKey, out var v) ? v : (double?)null).Append(m.Value).ToList();
            var earlier = last.Where(r => r.Values.ContainsKey(m.MetricKey)).Select(r => r.Values[m.MetricKey]).ToList();
            if (offField.TryGetValue(m.MetricKey, out var f))
            {
                var stored = new[] { f.Earlier3, f.Earlier2, f.Earlier1 }.Where(x => x is not null).Select(x => x!.Value).ToList();
                list.Add(new DataQualityNumber(m.MetricKey, DataQualityText.Group(m.MetricKey, m.Kind), m.Kind, m.Label, m.Value, stored.Count > 0 ? stored : earlier,
                    f.Expected, f.ChangePct, DataQualityNumber.Outside, "fill-drop", points, m.Step));
                continue;
            }
            if (off.TryGetValue(m.MetricKey, out var a))
            {
                var stored = a.EarlierOldestFirst.Where(x => x is not null).Select(x => x!.Value).ToList();
                list.Add(new DataQualityNumber(m.MetricKey, DataQualityText.Group(m.MetricKey, m.Kind), m.Kind, m.Label, m.Value, stored.Count > 0 ? stored : earlier,
                    a.Expected, a.ChangePct, DataQualityNumber.Outside, a.Rule, points, m.Step));
                continue;
            }
            if (compared && earlier.Count == Runs && Median(earlier) is { } expected)
                list.Add(new DataQualityNumber(m.MetricKey, DataQualityText.Group(m.MetricKey, m.Kind), m.Kind, m.Label, m.Value, earlier, expected,
                    Change(m.Kind, m.Value, expected, activeBase), DataQualityNumber.Within, null, points, m.Step));
            else
                list.Add(new DataQualityNumber(m.MetricKey, DataQualityText.Group(m.MetricKey, m.Kind), m.Kind, m.Label, m.Value, earlier, null, null,
                    DataQualityNumber.Learning, null, points, m.Step));
        }
        return list.OrderBy(n => DataQualityText.GroupOrder(n.Group)).ThenBy(n => n.Label, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// The changes behind one warning: the ones that concern its number, else (none does) every change of the run's window.
    public static (IReadOnlyList<DataQualityChange> Changes, bool Concerning) CauseOf(DataQualityAnomaly a, DataQualityDetail d)
    {
        if (d.CauseOf.TryGetValue(a.MetricKey, out var ids) && ids.Count > 0)
        {
            var set = ids.ToHashSet();
            var named = d.Changes.Where(c => set.Contains(c.ChangeId)).ToList();
            if (named.Count > 0) return (named, true);
        }
        return (d.Changes, false);
    }
}

/// A small trend line: the path of the points on a <see cref="Width"/> x <see cref="Height"/> box and where the newest is.
public sealed record DataQualitySpark(string Path, double LastX, double LastY, double Min, double Max, int Points)
{
    public const double Width = 96;
    public const double Height = 22;
}

/// The words of the panel, shared by the page and its tests (numbers in the viewer's regional format).
public static class DataQualityText
{
    public const string GroupSources = "Assets per source";
    public const string GroupCis = "CIs";
    public const string GroupClasses = "Assets per class";
    public const string GroupTiers = "Tier distribution";
    public const string GroupReports = "Report rows";
    public const string GroupKeyFill = "Key column fill";
    public const string GroupFieldFill = "Field fill per source";

    /// The groups in the order the panel lists them.
    public static readonly IReadOnlyList<string> Groups = [GroupSources, GroupCis, GroupClasses, GroupTiers, GroupReports, GroupKeyFill, GroupFieldFill];

    public static int GroupOrder(string group)
    {
        for (var i = 0; i < Groups.Count; i++) if (Groups[i] == group) return i;
        return Groups.Count;
    }

    /// Which group a key number belongs to (by its key, then its kind).
    public static string Group(string key, string kind)
    {
        if (key.StartsWith("fill.src.", StringComparison.OrdinalIgnoreCase)) return GroupFieldFill;
        if (key.StartsWith("fill.", StringComparison.OrdinalIgnoreCase) || kind == "fill") return GroupKeyFill;
        if (key.StartsWith("rows.", StringComparison.OrdinalIgnoreCase) || kind == "rows") return GroupReports;
        if (key.StartsWith("tier.", StringComparison.OrdinalIgnoreCase) || kind == "tier") return GroupTiers;
        if (key.StartsWith("class.", StringComparison.OrdinalIgnoreCase) || kind == "class") return GroupClasses;
        if (key.StartsWith("assets.", StringComparison.OrdinalIgnoreCase)) return GroupSources;
        return GroupCis;
    }

    /// A number as it is read: a fill with one decimal and "%", a count grouped.
    public static string Number(double? v, string kind, CultureInfo c)
    {
        if (v is not { } d) return "–";
        if (kind == "fill") return d.ToString("N1", c) + " %";
        return d == Math.Floor(d) ? d.ToString("N0", c) : d.ToString("N1", c);
    }

    /// The change: "-62 %", "+25 % of all active CIs", "-35.0 points".
    public static string Change(string kind, double? change, CultureInfo c)
    {
        if (change is not { } x) return "–";
        var sign = x > 0 ? "+" : "";
        return kind switch
        {
            "fill" => sign + x.ToString("N1", c) + " points",
            "tier" or "retire" or "class" => sign + x.ToString("N0", c) + " % of all active CIs",
            "classgap" => x.ToString("N0", c) + " to classify",
            _ => sign + x.ToString("N0", c) + " %",
        };
    }

    public static string Change(DataQualityAnomaly a, CultureInfo c) => Change(a.Kind, a.ChangePct, c);

    /// The three earlier values, oldest first: "1,020 / 1,000 / 990".
    public static string Expected(DataQualityAnomaly a, CultureInfo c) => string.Join(" / ", a.EarlierOldestFirst.Select(v => Number(v, a.Kind, c)));

    /// Earlier values, oldest first ("" when there is none yet).
    public static string Earlier(IEnumerable<double> values, string kind, CultureInfo c) => string.Join(" / ", values.Select(v => Number(v, kind, c)));

    /// What the rule found, in words.
    public static string Rule(string rule) => rule switch
    {
        "asset-drop" => "assets dropped",
        "report-zero" => "the report has no rows",
        "report-drop" => "the report lost rows",
        "fill-drop" => "fewer rows carry the value",
        "tier-shift" => "the tier moved",
        "retire-rise" => "many more CIs not seen",
        "class-shift" => "the asset class moved",
        DataQualityAnomaly.SourceRule => "the source fills fewer fields",
        DataQualityAnomaly.ClassificationRule => "something is not classified",
        _ => rule,
    };

    /// What changed, as one sentence: the number now, the three earlier values and the change. A one-per-source warning
    /// says how many fields and their average fill (the fields themselves are listed under it).
    public static string WhatChanged(DataQualityAnomaly a, CultureInfo c) => a.IsClassification
        ? $"{a.Label}: {Number(a.Now, a.Kind, c)}. Every finding must carry a risk rating, a tier 0-3 and an asset, and every active CI a tier 0-3 -- this is never compared with earlier runs: any count above 0 is a warning, and it clears itself on the first run where it is 0. The groups below say which reports or asset types and why."
        : a.IsSource
        ? $"{a.Label} at once. On average they are filled on {Number(a.Now, a.Kind, c)} of the source's records. The 3 runs before had {Expected(a, c)} (expected about {Number(a.Expected, a.Kind, c)}), so this run is {Change(a, c)} off -- {Rule(a.Rule)}."
        : $"{a.Label} is {Number(a.Now, a.Kind, c)}. The 3 runs before had {Expected(a, c)} (expected about {Number(a.Expected, a.Kind, c)}), so this run is {Change(a, c)} off -- {Rule(a.Rule)}.";

    /// The three earlier values of a field inside a one-per-source warning, oldest first.
    public static string Expected(DataQualityAnomalyField f, CultureInfo c) => string.Join(" / ", new[] { f.Earlier3, f.Earlier2, f.Earlier1 }.Select(v => Number(v, "fill", c)));

    /// The names of the fields inside a one-per-source warning ("" for any other warning).
    public static string FieldNames(IReadOnlyList<DataQualityAnomalyField> fields) => string.Join(", ", fields.Select(f => f.Name));

    /// Whether a run's mail went out and, if not, why -- in a few words (the history's column).
    public static string Mail(DataQualityRun r) => (r.MailState ?? "").ToLowerInvariant() switch
    {
        DataQualityMail.Sent => r.Anomalies == 0 ? "sent (back to normal)" : "sent",
        DataQualityMail.Failed => "not sent (failed)",
        DataQualityMail.Unchanged => "none (nothing changed)",
        DataQualityMail.DayLimit => "none (one a day)",
        DataQualityMail.Off => "none (the mail is off)",
        DataQualityMail.NoRecipients => "none (no recipients)",
        "" => "",
        var other => other,
    };

    /// Whether a run's mail went out and, if not, why -- as the sentence under the run's verdict ("" = nothing to say).
    /// <paramref name="mailOf"/>: for a run with the same warnings as the last mail, the run that mail was about.
    public static string MailWhy(DataQualityRun r, DataQualityRun? mailOf, Func<DateTime, string> time)
    {
        switch ((r.MailState ?? "").ToLowerInvariant())
        {
            case DataQualityMail.Sent:
                return r.Anomalies == 0
                    ? "A \"back to normal\" mail was sent for this run" + (r.MailedAt is { } b ? " at " + time(b) : "") + ": every key number is within its range again."
                    : "The data-quality mail for this run was sent" + (r.MailedAt is { } s ? " at " + time(s) : "") + ".";
            case DataQualityMail.Failed:
                return "The data-quality mail for this run was not sent: sending failed" + (r.MailedAt is { } f ? " at " + time(f) : "") + ". The next run tries again.";
            case DataQualityMail.Unchanged:
                return "No data-quality mail was sent for this run: nothing changed since the mail of "
                    + (mailOf is null ? "an earlier run" : "the run of " + time(mailOf.ComputedAt)) + ". A mail goes out only when the numbers outside their range change.";
            case DataQualityMail.DayLimit:
                return "No data-quality mail was sent for this run: one went out earlier the same day (at most one a day). The next run mails what is different then.";
            case DataQualityMail.Off:
                return "No data-quality mail was sent for this run: the mail is switched off (Settings > Guards (safety checks) > Data-quality warnings).";
            case DataQualityMail.NoRecipients:
                return "No data-quality mail was sent for this run: the mail has no recipients (Settings > Guards (safety checks) > Data-quality warnings).";
            default:
                return r.Anomalies > 0 ? "No data-quality mail was sent for this run." : "";
        }
    }

    /// What to do about a warning, in plain words (the fix; the re-run is the button next to it).
    public static string Fix(string rule) => rule switch
    {
        "asset-drop" => "Check that this source's collection ran completely (" + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/RunHealth") + ") and that no exclusion, scope or disabled-asset setting removed assets. Correct the setting, then re-run from the step that collects the source.",
        "report-zero" => "A report with no rows reads as if every finding was fixed. Check the report's exclusions and exemptions and that its query still returns rows. Correct it, then re-run Risk Analysis.",
        "report-drop" => "Check the report's exclusions and exemptions and whether a source it reads lost assets. Correct the setting, then re-run Risk Analysis.",
        "fill-drop" => "The value is missing on many more rows than before: either the source stopped delivering it, or the mapping, rule or factor that sets it was changed. Correct the mapping or rule, then re-run from the step that produces it.",
        "tier-shift" => "One tier rule or override can move many assets. Check the tier rules, overrides and classification changed recently. Correct the rule, then re-run from the step.",
        "retire-rise" => "Many assets were not seen in this run. Check that every collection ran and its source answered -- an asset that stays unseen retires after its grace period.",
        "class-shift" => "Many assets changed asset type. Check the asset type mapping and the classification rows changed recently. Correct them, then re-run from the step.",
        DataQualityAnomaly.ClassificationRule => "A report that gives a finding no tier means its asset (for an attack path: the target it reaches) has no CI with a tier; a CI without a tier means no tier rule matched it. Add or correct the tier rule (Configuration), or report the report to support when it emits no risk rating, then re-run from the step.",
        DataQualityAnomaly.SourceRule => "Many fields of one source going empty at once points at the source, not at one field: check that the source's collection ran completely and still has its permissions (" + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/RunHealth") + "), and whether the source's field mapping was changed. Correct it, then re-run from the step that collects the source.",
        _ => "Check the settings changed recently, correct the one that caused this, then re-run from the step.",
    };

    /// The pipeline step to re-run from, by its label on Admin > Jobs.
    public static string Step(string? step) => string.IsNullOrWhiteSpace(step) ? "" : SI.Management.Web.Jobs.JobSchedule.Label(step);

    /// The status of a key number, in words.
    public static string Status(string status) => status switch
    {
        DataQualityNumber.Outside => "outside the range",
        DataQualityNumber.Within => "within the range",
        _ => "no range yet",
    };

    /// One settings change as it is read: "exclusions/global (document) changed by x at 2026-10-11 09:12 UTC".
    public static string ChangeWords(DataQualityChange ch)
    {
        var scope = string.IsNullOrWhiteSpace(ch.Scope) || ch.Scope == "solution" ? "" : " (" + ch.Scope + ")";
        var by = string.IsNullOrWhiteSpace(ch.ChangedBy) ? "" : " changed by " + ch.ChangedBy;
        return ch.Name + scope + by + " at " + ch.ChangedAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
    }

    /// The audit trail filtered to one changed setting (the trail's own name filter).
    public static string ChangeLink(DataQualityChange ch) => "/Admin/History?name=" + Uri.EscapeDataString(ch.Name);

    /// The verdict of a run in a few words (the history's column).
    public static string Verdict(DataQualityRun r, CultureInfo c) =>
        r.Learning ? "no range yet" : r.Anomalies == 0 ? "within the range" : r.Anomalies.ToString("N0", c) + " outside the range";

    /// The trend line of a number over the runs (null = that run did not measure it); null with fewer than 2 values.
    public static DataQualitySpark? Spark(IReadOnlyList<double?> values)
    {
        var have = values.Select((v, i) => (v, i)).Where(x => x.v is not null).Select(x => (V: x.v!.Value, I: x.i)).ToList();
        if (have.Count < 2) return null;
        double min = have.Min(x => x.V), max = have.Max(x => x.V);
        var span = max - min;
        const double pad = 2;
        var steps = Math.Max(1, values.Count - 1);
        double X(int i) => Math.Round(pad + (DataQualitySpark.Width - 2 * pad) * i / steps, 2);
        double Y(double v) => Math.Round(span <= 0 ? DataQualitySpark.Height / 2 : pad + (DataQualitySpark.Height - 2 * pad) * (1 - (v - min) / span), 2);
        static string R(double v) => v.ToString("0.##", CultureInfo.InvariantCulture);
        var path = string.Join(" ", have.Select((p, n) => (n == 0 ? "M" : "L") + R(X(p.I)) + " " + R(Y(p.V))));
        var end = have[^1];
        return new DataQualitySpark(path, X(end.I), Y(end.V), min, max, have.Count);
    }
}
