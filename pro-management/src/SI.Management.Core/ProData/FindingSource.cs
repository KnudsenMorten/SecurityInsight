using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

/// <summary>
/// #1332 THE READERS ON THE FINDING HISTORY (docs/DESIGN.md "Finding history model", "The readers"; owner 2026-11-23: the
/// new model serves, the old model is built every run as the check). Every statement the web app and the MCP server send
/// goes through ONE place (the SQL seams: the web app's executor, Core's <see cref="SqlReader"/>); there a statement that
/// READS sidata.Finding / sidata.vExemptedFinding / sidata.vCurrentFinding is sent to sidata.vFinding /
/// sidata.vExemptedFindingServed / sidata.vCurrentFindingServed (sql/si-data-schema.sql). Those give every collection back
/// either as its stored rows or as its history -- the history only for a collection whose every compare of its run was the
/// same, and the published collection only when its publish pointer says so (sidata.FindingSourceOf).
/// A statement that WRITES the findings is never changed, nor a quoted name (OBJECT_ID('sidata.Finding')). While no
/// collection is served from the history (sidata.FindingSourceActive, asked at most once a minute per database), or on a
/// database without these objects, every statement goes exactly as written -- the pages read the tables as before.
/// The engine's reader jobs do the same (engine/_shared/data-sql/SI-FindingSource.ps1: the same rules, the same cases).
/// </summary>
public static class FindingSource
{
    /// The names a reader reads -> the served views.
    public static readonly IReadOnlyList<(string From, string To)> Routes =
    [
        ("sidata.Finding", "sidata.vFinding"),
        ("sidata.vExemptedFinding", "sidata.vExemptedFindingServed"),
        ("sidata.vCurrentFinding", "sidata.vCurrentFindingServed"),
    ];

    /// The source lists (sidata.FindingSourceLists): the collections read from their history, every other one, the newest id.
    /// A database without them answers no served collection.
    public const string ListsSql =
        "SET NOCOUNT ON; IF OBJECT_ID(N'sidata.FindingSourceLists') IS NULL OR OBJECT_ID(N'sidata.vFinding') IS NULL " +
        "SELECT CAST(N'[]' AS nvarchar(max)) AS Served, CAST(N'[]' AS nvarchar(max)) AS Stored, 0 AS MaxId " +
        "ELSE EXEC (N'SELECT Served, Stored, MaxId FROM sidata.FindingSourceLists()');";

    /// The most characters a list may have (one session-context value); longer = not active (the tables, as before).
    public const int MaxListChars = 3800;

    /// The ids a collection made after an answer can take within its cache time (read from their stored rows).
    public const int AheadIds = 20;

    /// One answer of <see cref="ListsSql"/>.
    public sealed record Lists(string Served, string Stored, long MaxId)
    {
        private static readonly Regex Ids = new(@"^\[(\d+(,\d+)*)?\]$", RegexOptions.CultureInvariant);
        /// A collection is served and both lists are lists of ids that fit.
        public bool Active => Served != "[]" && Ids.IsMatch(Served) && Ids.IsMatch(Stored) && Served.Length <= MaxListChars && Stored.Length <= MaxListChars;
        public static readonly Lists None = new("[]", "[]", 0);
        /// The statement that hands one statement its lists (session context of its connection).
        public string ContextSql() =>
            $"EXEC sys.sp_set_session_context @key = N'si.finding.served', @value = N'{Served}'; " +
            $"EXEC sys.sp_set_session_context @key = N'si.finding.stored', @value = N'{Stored}'; " +
            $"EXEC sys.sp_set_session_context @key = N'si.finding.maxid', @value = {MaxId.ToString(System.Globalization.CultureInfo.InvariantCulture)};";
        /// The lists' row (Served, Stored, MaxId) as an answer; anything else = none.
        public static Lists From(IReadOnlyDictionary<string, object?>? row)
        {
            if (row is null) return None;
            string S(string k) => row.TryGetValue(k, out var v) && v is not null && v is not DBNull ? Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "[]" : "[]";
            var mx = row.TryGetValue("MaxId", out var m) && m is not null && m is not DBNull ? Convert.ToInt64(m, System.Globalization.CultureInfo.InvariantCulture) : 0L;
            var stored = S("Stored");
            // the ids a collection made AFTER this answer can take within its cache time: read from their stored rows
            if (Ids.IsMatch(stored))
            {
                var ahead = string.Join(",", Enumerable.Range(1, AheadIds).Select(i => (mx + i).ToString(System.Globalization.CultureInfo.InvariantCulture)));
                stored = stored == "[]" ? "[" + ahead + "]" : stored[..^1] + "," + ahead + "]";
            }
            return new Lists(S("Served"), stored, mx);
        }
    }

    private const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline;
    private const string Table = @"(?:\[?sidata\]?\.\[?Finding\]?)(?![A-Za-z0-9_\]])";
    private static readonly Regex Mention = new(@"sidata\.(?:Finding|vExemptedFinding|vCurrentFinding)(?![A-Za-z0-9_])", O);
    private static readonly Regex WriteTarget = new(@"\b(?:UPDATE|INSERT(?:\s+INTO)?|DELETE(?:\s+TOP\s*\(\s*[^)]*\))?(?:\s+FROM)?|MERGE(?:\s+INTO)?|TRUNCATE\s+TABLE|ALTER\s+TABLE|ON|INTO)\s+" + Table, O);
    private static readonly Regex AliasOf = new(Table + @"\s+(?:AS\s+)?([A-Za-z_][A-Za-z0-9_]*)", O);
    private static readonly HashSet<string> Keywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "AS", "WITH", "WHERE", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "OUTER", "ON", "GROUP", "ORDER", "UNION", "SET", "SELECT",
        "FROM", "AND", "OR", "OPTION", "PIVOT", "UNPIVOT", "TABLESAMPLE",
    };
    private static readonly IReadOnlyList<(Regex Rx, string To)> Replacers =
        Routes.Select(r => (new Regex(@"(?<![A-Za-z0-9_.'\[\]])" + Regex.Escape(r.From) + "(?![A-Za-z0-9_])", O), r.To)).ToList();

    /// Does the statement WRITE sidata.Finding (a write target, an index ON it, an UPDATE / DELETE through its alias)?
    public static bool Writes(string sql)
    {
        if (string.IsNullOrEmpty(sql)) return false;
        if (WriteTarget.IsMatch(sql)) return true;
        foreach (Match m in AliasOf.Matches(sql))
        {
            var a = m.Groups[1].Value;
            if (Keywords.Contains(a)) continue;
            if (Regex.IsMatch(sql, @"\b(?:UPDATE|DELETE(?:\s+TOP\s*\(\s*[^)]*\))?(?:\s+FROM)?)\s+" + Regex.Escape(a) + @"\b(?!\.)", O)) return true;
        }
        return false;
    }

    /// A reader that keeps today's stored rows while its history plan is slower (the findings list: REQUIREMENTS #1332 --
    /// "findings list stays on the stored rows until its history plan is at or below today's"): a statement that carries it is
    /// never routed. The per-run compare still compares that reader's statement (SI-DataHistoryServe.ps1, 'findings page').
    public const string StoredMarker = "/* si.finding.source: stored */";

    // ---- a READER that keeps today's stored rows (the findings list: the raw findings grid and the findings browser) ----------
    private static readonly AsyncLocal<int> StoredDepth = new();

    /// While the returned scope is open, every statement this flow sends goes exactly as written (today's stored rows) --
    /// the findings list (REQUIREMENTS #1332: "findings list stays on the stored rows until its history plan is at or below
    /// today's"). The per-run reader compare still compares its statement.
    public static IDisposable KeepStored() { StoredDepth.Value++; return new StoredScope(); }

    /// Is this flow inside <see cref="KeepStored"/>?
    public static bool KeepingStored => StoredDepth.Value > 0;

    private sealed class StoredScope : IDisposable
    {
        private bool _done;
        public void Dispose() { if (_done) return; _done = true; StoredDepth.Value--; }
    }
    /// Does the statement name one of the routed names at all (no probe is needed for one that does not)?
    public static bool Mentions(string sql) => !string.IsNullOrEmpty(sql) && Mention.IsMatch(sql);

    /// The statement with every READ of the routed names sent to the served views; unchanged when it writes the findings.
    public static string Route(string sql)
    {
        if (!Mentions(sql) || Writes(sql) || sql.Contains(StoredMarker, StringComparison.Ordinal)) return sql;
        var o = sql;
        foreach (var (rx, to) in Replacers) o = rx.Replace(o, to);
        return o;
    }

    // ---- the cached lists, per database -----------------------------------------------------------------------------------
    private static readonly ConcurrentDictionary<string, (Lists L, DateTime At)> Answers = new(StringComparer.OrdinalIgnoreCase);

    /// How long one answer is used. The source is decided ONCE per statement from it: a collection that stops being served
    /// keeps its (verified) history this long at most -- the engine's history step waits longer before it removes members
    /// it served (SI-DataHistory.ps1, CacheSeconds + 5).
    public static TimeSpan CacheFor { get; set; } = TimeSpan.FromSeconds(15);

    /// Forgets every cached answer (tests).
    public static void Forget() => Answers.Clear();

    /// The statement to send: while the database serves any collection from its history, its reads of the findings go to the
    /// served views and the statement is handed its source lists first; otherwise exactly as written. -probe asks the
    /// database (<see cref="ListsSql"/>); a probe that fails = none served.
    public static async Task<string> RouteAsync(string sql, string database, Func<CancellationToken, Task<Lists>> probe, CancellationToken ct)
    {
        if (!Mentions(sql) || KeepingStored) return sql;
        var now = DateTime.UtcNow;
        if (!Answers.TryGetValue(database, out var a) || now - a.At >= CacheFor)
        {
            Lists l;
            try { l = await probe(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch { l = Lists.None; }
            a = (l, now);
            Answers[database] = a;
        }
        if (!a.L.Active) return sql;
        var routed = Route(sql);
        return ReferenceEquals(routed, sql) || routed == sql ? sql : a.L.ContextSql() + "\n" + routed;
    }
}