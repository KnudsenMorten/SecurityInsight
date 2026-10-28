using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Data;

namespace SI.Management.Web.Audit;

/// One row of the Audit view.
public sealed record AuditRow(long Id, DateTime? TsUtc, string RecordType, string Action, string Category, string Actor, string? ActorSource,
    string? Target, string? Reason, string Outcome, string? OutcomeText, bool WhatIf, string? CorrelationId, string? ScopeDomain, int? ScopeDepartmentId,
    string? BeforeJson, string? AfterJson, long Changes)
{
    public static AuditRow From(IReadOnlyDictionary<string, object?> r)
    {
        string? S(string k) => r.TryGetValue(k, out var v) && v is not null && v is not DBNull ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
        long L(string k) => r.TryGetValue(k, out var v) && v is not null && v is not DBNull ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : 0;
        var when = r.TryGetValue("Ts", out var t) && t is DateTime d ? d : (DateTime?)null;
        var dep = r.TryGetValue("Department", out var dv) && dv is not null && dv is not DBNull ? Convert.ToInt32(dv, CultureInfo.InvariantCulture) : (int?)null;
        var wi = r.TryGetValue("WhatIf", out var w) && w is not null && w is not DBNull && Convert.ToInt32(w, CultureInfo.InvariantCulture) == 1;
        return new AuditRow(L("Id"), when, S("Kind") ?? "event", S("Action") ?? "", S("Category") ?? "", S("Actor") ?? "", S("Source"), S("Target"), S("Reason"),
            S("Outcome") ?? "", S("OutcomeText"), wi, S("Correlation"), S("Domain"), dep, S("BeforeJson"), S("AfterJson"), L("Changes"));
    }
}

/// Who may see which rows of the trail (AUDIT-1.3): Admin and up everything; a Delegated user the rows whose target lies
/// in their scope (the domain / department recorded on the row) plus what they did themselves; nobody else.
public sealed record AuditVisibility(bool All, bool AnyDomain, IReadOnlyList<string> Domains, IReadOnlyList<int> Departments, string? Me)
{
    public static AuditVisibility? Of(ClaimsPrincipal user)
    {
        if (user.IsAdmin()) return new(true, false, Array.Empty<string>(), Array.Empty<int>(), null);
        if (!user.IsDelegated()) return null;
        var scopes = user.Scopes();
        var domains = scopes.SelectMany(s => s.ValuesOf(ScopeTypes.Domain)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var deps = scopes.SelectMany(s => s.ValuesOf(ScopeTypes.Department))
            .Select(v => int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : 0).Where(n => n > 0).Distinct().ToList();
        return new(false, domains.Contains(AccessScope.AnyDomain), domains.Where(d => d != AccessScope.AnyDomain).ToList(), deps, AuditScope.ActorOf(user));
    }

    public string Describe() => All ? "the whole trail"
        : "the rows in your scope (" + string.Join(", ", (AnyDomain ? new[] { "every domain" } : Domains).Concat(Departments.Select(d => "department " + d))) + ") and your own actions";
}

/// <summary>
/// The Audit view's reads (AUDIT-1.4) -- server-side: newest first, paged, sorted and filtered by the shared grid
/// statement builder (<see cref="GridSql"/>: every value a parameter, sort whitelisted), over cfg.AuditEvent. A change row
/// whose event is on the trail is shown under that event (its change summary), not as a row of its own. Read-only:
/// nothing here writes.
/// </summary>
public sealed class AuditTrailReader
{
    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.AuditEvent') IS NULL THEN 0 ELSE 1 END AS HasTable;";

    public const string Source = """
SELECT a.Id AS Id, a.TsUtc AS Ts, a.RecordType AS Kind, a.Action AS Action, LEFT(a.Action, CHARINDEX(N'.', a.Action + N'.') - 1) AS Category,
       a.Actor AS Actor, a.ActorSource AS Source, a.Target AS Target, a.Reason AS Reason, a.Outcome AS Outcome, a.OutcomeText AS OutcomeText,
       CAST(a.WhatIf AS INT) AS WhatIf, a.CorrelationId AS Correlation, a.ScopeDomain AS Domain, a.ScopeDepartmentId AS Department,
       LEFT(a.BeforeJson, 4000) AS BeforeJson, LEFT(a.AfterJson, 4000) AS AfterJson,
       CASE WHEN a.RecordType = N'event' AND a.CorrelationId IS NOT NULL
            THEN (SELECT COUNT_BIG(*) FROM cfg.AuditEvent AS d WHERE d.CorrelationId = a.CorrelationId AND d.RecordType = N'change') ELSE 0 END AS Changes
FROM cfg.AuditEvent AS a
WHERE (a.RecordType = N'event' OR a.CorrelationId IS NULL
       OR NOT EXISTS (SELECT 1 FROM cfg.AuditEvent AS e WHERE e.CorrelationId = a.CorrelationId AND e.RecordType = N'event'))
  AND (@From IS NULL OR a.TsUtc >= @From) AND (@To IS NULL OR a.TsUtc < @To)
  AND (@AllRows = 1 OR a.Actor = @Me
       OR (@AnyDomain = 1 AND a.ScopeDomain IS NOT NULL)
       OR a.ScopeDomain IN (SELECT sd.[value] FROM OPENJSON(@Domains) AS sd)
       OR a.ScopeDepartmentId IN (SELECT TRY_CONVERT(INT, sp.[value]) FROM OPENJSON(@Departments) AS sp))
""";

    /// The change rows of the events on a page (their change summary).
    public const string ChangesSql = """
SELECT d.Id, d.TsUtc AS Ts, d.RecordType AS Kind, d.Action, LEFT(d.Action, CHARINDEX(N'.', d.Action + N'.') - 1) AS Category, d.Actor, d.ActorSource AS Source,
       d.Target, d.Reason, d.Outcome, d.OutcomeText, CAST(d.WhatIf AS INT) AS WhatIf, d.CorrelationId AS Correlation, d.ScopeDomain AS Domain,
       d.ScopeDepartmentId AS Department, LEFT(d.BeforeJson, 4000) AS BeforeJson, LEFT(d.AfterJson, 4000) AS AfterJson, CAST(0 AS BIGINT) AS Changes
FROM cfg.AuditEvent AS d
WHERE d.RecordType = N'change' AND d.CorrelationId IN (SELECT c.[value] FROM OPENJSON(@Correlations) AS c)
ORDER BY d.Id;
""";

    public static readonly GridSpec Spec = GridSql.Check(new GridSpec("audit", "", Source,
    [
        // sorted as an expression: the grid always adds the key column as the tie-breaker, and SQL Server refuses the same
        // column twice in ORDER BY (found by AuditLocalSqlTests)
        new GridColumn("Id", "#", GridType.Number, GridFilter.Range, SortSql: "(g.[Id] + 0)"),
        new GridColumn("Ts", "When", GridType.Date),
        new GridColumn("Category", "Category", GridType.Text, GridFilter.Values),
        new GridColumn("Action", "Action", GridType.Text, GridFilter.Contains, Search: true),
        new GridColumn("Actor", "Actor", GridType.Text, GridFilter.Contains, Search: true),
        new GridColumn("Source", "Source", GridType.Text, GridFilter.Values),
        new GridColumn("Target", "Target", GridType.Text, GridFilter.Contains, Search: true),
        new GridColumn("Outcome", "Outcome", GridType.Text, GridFilter.Values, Search: true),
        new GridColumn("Reason", "Reason", GridType.Text, GridFilter.Contains, Search: true),
        new GridColumn("Domain", "Domain", GridType.Text, GridFilter.Values),
        new GridColumn("WhatIf", "Plan", GridType.Flag, GridFilter.Values),
        new GridColumn("Changes", "Changes", GridType.Number, Sortable: true),
        new GridColumn("OutcomeText", "Detail", GridType.Text, Search: true, Sortable: false, Hidden: true),
        new GridColumn("BeforeJson", "Before", GridType.Text, Search: true, Sortable: false, Hidden: true),
        new GridColumn("AfterJson", "After", GridType.Text, Search: true, Sortable: false, Hidden: true),
        new GridColumn("Kind", "Record", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("Correlation", "Correlation", GridType.Text, Sortable: false, Hidden: true),
        new GridColumn("Department", "Department", GridType.Number, Sortable: false, Hidden: true),
    ], DefaultSort: "Ts", DefaultDesc: true, KeyColumn: "Id",   // #317: newest first, on the When column (▼ shown there)
    SourceParameters: ["From", "To", "AllRows", "Me", "AnyDomain", "Domains", "Departments"], Immutable: false));

    private readonly ISqlExecutor _sql;
    public AuditTrailReader(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> ExistsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("HasTable") == 1;

    public static IReadOnlyDictionary<string, object?> SourceParams(AuditVisibility v, DateTime? from, DateTime? to) => new Dictionary<string, object?>
    {
        ["From"] = from, ["To"] = to, ["AllRows"] = v.All ? 1 : 0, ["Me"] = v.Me, ["AnyDomain"] = v.AnyDomain ? 1 : 0,
        ["Domains"] = JsonSerializer.Serialize(v.Domains), ["Departments"] = JsonSerializer.Serialize(v.Departments.Select(d => d.ToString(CultureInfo.InvariantCulture))),
    };

    public async Task<(IReadOnlyList<AuditRow> Rows, long Total, string Query)> PageAsync(GridState st, AuditVisibility v, DateTime? from, DateTime? to, CancellationToken ct)
    {
        var q = GridSql.Page(Spec, st, SourceParams(v, from, to));
        var rows = await _sql.QueryAsync(q.Text, q.Parameters, ct);
        var total = rows.FirstOrDefault()?.Long("TotalRows") ?? 0;
        return (rows.Select(AuditRow.From).ToList(), total, q.Text);
    }

    /// #287: how many events each value of one value-filter column has under the OTHER filters and the reader's visibility.
    public async Task<IReadOnlyList<(string Value, long N)>> ValueCountsAsync(GridState st, AuditVisibility v, DateTime? from, DateTime? to, string column, CancellationToken ct)
    {
        var q = GridSql.ValueCounts(Spec, st, SourceParams(v, from, to), column);
        return (await _sql.QueryAsync(q.Text, q.Parameters, ct)).Select(r => (r.Str("V") ?? "", r.Long("N") ?? 0)).ToList();
    }

    /// EVERY row of the filtered trail, in pages of <paramref name="chunk"/> -- the export is of the whole result.
    public async IAsyncEnumerable<AuditRow> AllAsync(GridState st, AuditVisibility v, DateTime? from, DateTime? to, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct, int chunk = 5000)
    {
        for (var page = 1; ; page++)
        {
            var q = GridSql.Page(Spec, st with { Page = page, Size = chunk }, SourceParams(v, from, to));
            var rows = await _sql.QueryAsync(q.Text, q.Parameters, ct);
            foreach (var r in rows) yield return AuditRow.From(r);
            if (rows.Count < chunk) yield break;
        }
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<AuditRow>>> ChangesAsync(IEnumerable<string> correlations, CancellationToken ct)
    {
        var ids = correlations.Where(c => !string.IsNullOrEmpty(c)).Distinct(StringComparer.Ordinal).ToList();
        if (ids.Count == 0) return new Dictionary<string, IReadOnlyList<AuditRow>>();
        var rows = await _sql.QueryAsync(ChangesSql, new Dictionary<string, object?> { ["Correlations"] = JsonSerializer.Serialize(ids) }, ct);
        return rows.Select(AuditRow.From).Where(r => r.CorrelationId is not null).GroupBy(r => r.CorrelationId!, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<AuditRow>)g.ToList(), StringComparer.Ordinal);
    }
}

/// The before -> after summary of a row: per field of a JSON object, or the two values when they are not objects.
public static class AuditDiff
{
    public sealed record Line(string Field, string? Before, string? After);

    public static IReadOnlyList<Line> Of(string? before, string? after)
    {
        var b = Parse(before); var a = Parse(after);
        if (b is { ValueKind: JsonValueKind.Object } || a is { ValueKind: JsonValueKind.Object })
        {
            var bo = Props(b); var ao = Props(a);
            return bo.Keys.Union(ao.Keys, StringComparer.Ordinal).OrderBy(k => k, StringComparer.Ordinal)
                .Select(k => new Line(k, bo.GetValueOrDefault(k), ao.GetValueOrDefault(k)))
                .Where(l => !string.Equals(l.Before, l.After, StringComparison.Ordinal) || before is null)
                .Take(40).ToList();
        }
        if (before is null && after is null) return Array.Empty<Line>();
        return [new Line("", Text(b, before), Text(a, after))];
    }

    private static JsonElement? Parse(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        try { using var d = JsonDocument.Parse(s); return d.RootElement.Clone(); } catch (JsonException) { return null; }
    }

    private static Dictionary<string, string?> Props(JsonElement? e) =>
        e is { ValueKind: JsonValueKind.Object } o ? o.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).ToDictionary(g => g.Key, g => Text(g.First().Value, null), StringComparer.Ordinal)
        : new Dictionary<string, string?>(StringComparer.Ordinal);

    private static string? Text(JsonElement? e, string? raw) => e switch
    {
        null => raw,
        { ValueKind: JsonValueKind.String } s => s.GetString(),
        { ValueKind: JsonValueKind.Null } => null,
        { } x => x.GetRawText(),
    };
}
