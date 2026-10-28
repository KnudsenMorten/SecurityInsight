using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SI.Management.Core.ProData;

/// <summary>
/// THE PIVOT BUILDER of the weighted risk page (#360): rows, columns, filters and values chosen from a FIXED list
/// (<see cref="PivotSql.Fields"/>, <see cref="PivotSql.Measures"/>) and answered in SQL from one collection's findings.
/// <para>NO FREE SQL. A field or measure is a KEY; the statement is assembled only from the whitelisted expressions
/// those keys name, so a key that is not in the list is refused before anything is built, and a filter VALUE is never
/// text in the statement -- it travels as a JSON parameter read by OPENJSON. The statement is read-only
/// (<see cref="SqlGuard"/>) and reads one collection (its "this collection" condition is the same text the department
/// scope narrows, so a department-scoped user's pivot counts only their departments' findings).</para>
/// <para>COUNTING: a finding counts once per row/column cell it falls in. The Service fields join the collection's
/// service membership (sidata.ServiceMember): a finding on a CI in two services counts under EACH service, as on the
/// Services view -- so with a Service field the totals add up to more than the collection's.</para>
/// </summary>
public static class PivotSql
{
    /// A field: its key (URL + SQL alias), its label, the SQL over the finding row (f), its asset (a), its service
    /// membership (sm) and the CMDB's criticality per service key (crit), and what it needs joined.
    public sealed record Field(string Key, string Label, string Expr, bool Asset = false, bool Service = false, bool Cmdb = false, bool Department = false);

    /// A measure: its key, label, and aggregate over the base rows (b).
    public sealed record Measure(string Key, string Label, string Agg, bool Score = true);

    public const string NoService = WeightedServiceSql.NoServiceName;

    public static readonly IReadOnlyList<Field> Fields =
    [
        new("service", "Service", $"COALESCE(NULLIF(sm.ServiceName, N''), sm.ServiceKey, N'{NoService}')", Service: true),
        new("criticality", "Service criticality",
            $"CASE WHEN sm.ServiceKey IS NULL THEN N'{NoService}' ELSE COALESCE(NULLIF(SUBSTRING(crit.CritKey, 3, 64), N''), N'{WeightedServiceSql.NotSet}') END", Service: true, Cmdb: true),
        new("owner", "Service owner", $"CASE WHEN sm.ServiceKey IS NULL THEN N'{NoService}' ELSE COALESCE(NULLIF(crit.Owner, N''), N'(none)') END", Service: true, Cmdb: true),
        new("department", "Department", "COALESCE(d.Name, N'Unassigned')", Department: true),
        new("assetkind", "Asset kind", "COALESCE(NULLIF(a.AssetKind, N''), N'(none)')", Asset: true),
        new("asset", "Asset", "COALESCE(NULLIF(f.AssetName, N''), f.AssetKey, N'(none)')"),
        new("tier", "Tier", ProDataSql.TierExpr("f.Tier")),
        new("domain", "Domain", "COALESCE(NULLIF(f.SecurityDomain, N''), N'(none)')"),
        new("report", "Report", "COALESCE(NULLIF(f.ReportName, N''), N'(none)')"),
        new("severity", "Severity", "COALESCE(NULLIF(f.Severity, N''), N'(none)')"),
        new("issue", "CVE / issue", "COALESCE(f.Cve, f.ConfigurationId, N'(none)')"),
    ];

    public static readonly IReadOnlyList<Measure> Measures =
    [
        new("findings", "Findings", "COUNT_BIG(*)", Score: false),
        new("assets", "Assets", "COUNT_BIG(DISTINCT b.AssetKey)", Score: false),
        new("risk", "Risk total", "SUM(b.RiskScore)"),
        new("weighted", "Weighted total", "SUM(b.RiskScoreWeighted)"),
        new("highest", "Highest weighted", "MAX(b.RiskScoreWeighted)"),
        new("average", "Average weighted", "AVG(b.RiskScoreWeighted)"),
    ];

    public const int MaxRows = 3;
    public const int MaxColumns = 2;
    public const int MaxValues = 6;
    public const int MaxFilters = 6;
    public const int MaxFilterValues = GridSql.MaxValues;
    /// The most groups one pivot reads (cells + totals); more = the answer says it was cut and asks to filter.
    public const int MaxGroups = 20_000;
    /// The most column values one pivot shows (the largest first); the rest are left out of the columns, never of the totals.
    public const int MaxColumnValues = 40;
    /// The most values a filter's choice list offers.
    public const int MaxChoices = 200;

    public static Field? FieldOf(string? key) => Fields.FirstOrDefault(f => string.Equals(f.Key, key, StringComparison.OrdinalIgnoreCase));
    public static Measure? MeasureOf(string? key) => Measures.FirstOrDefault(m => string.Equals(m.Key, key, StringComparison.OrdinalIgnoreCase));

    private static Field F(string key) => FieldOf(key) ?? throw new ArgumentException($"'{Short(key)}' is not a pivot field");
    private static Measure M(string key) => MeasureOf(key) ?? throw new ArgumentException($"'{Short(key)}' is not a pivot measure");
    private static string Short(string? s) => s is null ? "" : s.Length > 40 ? s[..40] + "…" : s;

    /// <summary>
    /// A request as the URL carries it, validated: only known keys (an unknown one is REFUSED -- ArgumentException), each
    /// field in one zone only (rows win over columns, columns over filters), the limits, filter values free text checked
    /// like every grid filter. The sort is a row field, a measure (its row total) or "measure|column value".
    /// </summary>
    public static PivotRequest Normalize(IEnumerable<string?> rows, IEnumerable<string?> columns, IEnumerable<string?> values,
        IEnumerable<string?> filters, IReadOnlyDictionary<string, IReadOnlyList<string>>? filterValues, string? sort, bool? desc)
    {
        static List<string> Keys(IEnumerable<string?> s, Func<string, string> canon) =>
            s.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => canon(x!.Trim())).Distinct(StringComparer.Ordinal).ToList();
        var r = Keys(rows, k => F(k).Key);
        var c = Keys(columns, k => F(k).Key).Where(k => !r.Contains(k)).ToList();
        var v = Keys(values, k => M(k).Key);
        var fl = Keys(filters, k => F(k).Key).Where(k => !r.Contains(k) && !c.Contains(k)).ToList();
        if (r.Count > MaxRows) throw new ArgumentException($"at most {MaxRows} row fields");
        if (c.Count > MaxColumns) throw new ArgumentException($"at most {MaxColumns} column fields");
        if (v.Count > MaxValues) throw new ArgumentException($"at most {MaxValues} values");
        if (fl.Count > MaxFilters) throw new ArgumentException($"at most {MaxFilters} filters");
        if (v.Count == 0) v.Add("weighted");
        var fv = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (k, vals) in filterValues ?? new Dictionary<string, IReadOnlyList<string>>())
        {
            var key = F(k).Key;
            var clean = vals.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => ProDataFilters.Text(x)!).Distinct(StringComparer.Ordinal).ToList();
            if (clean.Count > MaxFilterValues) throw new ArgumentException($"at most {MaxFilterValues} values per filter");
            if (clean.Count == 0) continue;
            if (!fl.Contains(key) && !r.Contains(key) && !c.Contains(key))
            {
                if (fl.Count >= MaxFilters) throw new ArgumentException($"at most {MaxFilters} filters");
                fl.Add(key);
            }
            fv[key] = clean;
        }
        string? s = null;
        if (!string.IsNullOrWhiteSpace(sort))
        {
            var t = sort.Trim();
            var bar = t.IndexOf('|');
            var head = bar < 0 ? t : t[..bar];
            if (FieldOf(head) is { } sf && bar < 0 && r.Contains(sf.Key)) s = sf.Key;
            else if (MeasureOf(head) is { } sm && v.Contains(sm.Key)) s = bar < 0 ? sm.Key : sm.Key + "|" + (ProDataFilters.Text(t[(bar + 1)..]) ?? "");
        }
        s ??= v[0];
        var d = desc ?? (MeasureOf(s.Split('|')[0]) is not null);
        return new PivotRequest(r, c, v, fl, fv, s, d);
    }

    private static string P(string key) => "PF_" + key;

    /// <summary>
    /// The pivot's statement: a base CTE (b) of the collection's findings with ONLY the fields this request uses, then
    /// one GROUPING SETS read -- the cells (rows x columns), the row totals, the column totals and the grand total -- so a
    /// distinct count, a highest and an average are right in every total (never summed from the cells).
    /// <paramref name="cmdb"/>: the CMDB tables exist (else the criticality / owner read the empty key set).
    /// <paramref name="visibility"/>: a department-scoped user's row predicate over f (null = sees everything).
    /// </summary>
    /// #855 <paramref name="lifecycle"/>: the CI lifecycle the pivot counts (sidata.Finding.CiLifecycle); null = no lifecycle
    /// condition (the reader passes the person's choice, active by default).
    public static SqlQuery Build(PivotRequest q, string collectionId, bool cmdb, RowVisibility? visibility = null, int max = MaxGroups, LifecycleFilter? lifecycle = null) =>
        Compose(q, collectionId, cmdb, visibility, max, cube: null, lifecycle);

    /// <summary>
    /// #812: the same pivot read from the collection's stored cube (sidata.PivotCell, written once per collection by the data
    /// sync -- engine\pro-data\_shared\SI-DataPivots.ps1): one row per CI x tier x domain x report x severity x department x
    /// service x exempted-or-not, with the findings, the risk and weighted sums, the highest weighted score and how many have
    /// one. The base CTE reads those rows (thousands, not a million) under the finding alias, so every field's expression is
    /// the live one; the measures are their exact roll-ups (the distinct assets counted over the CI key, the average = the
    /// weighted sum over its count). <paramref name="excluding"/>: exempted findings left out (the cube's Exempted rows).
    /// Only for a request the cube can answer (<see cref="Storable"/>) and an account that sees every department (a
    /// department-limited account keeps the live read restricted to its findings -- the cube spans every department).
    /// </summary>
    public static SqlQuery BuildStored(PivotRequest q, string collectionId, bool cmdb, bool excluding, int max = MaxGroups, LifecycleFilter? lifecycle = null) =>
        Storable(q) ? Compose(q, collectionId, cmdb, null, max, cube: excluding, lifecycle)
                    : throw new ArgumentException("this pivot names the CVE / issue field, which the stored cube does not carry");

    /// The fields the stored cube carries: every field but the CVE / issue (one row per CVE is on Vulnerabilities).
    public static bool Storable(PivotRequest q) => !q.FieldsUsed.Contains("issue", StringComparer.Ordinal);

    /// The roll-up of each measure over the cube's rows (b carries NFind, RiskSum, WeightedSum, WeightedMax, WeightedN).
    private static readonly IReadOnlyDictionary<string, string> CubeAgg = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["findings"] = "SUM(b.NFind)",
        ["assets"] = "COUNT_BIG(DISTINCT b.AssetKey)",
        ["risk"] = "SUM(b.RiskSum)",
        ["weighted"] = "SUM(b.WeightedSum)",
        ["highest"] = "MAX(b.WeightedMax)",
        ["average"] = "SUM(b.WeightedSum) / NULLIF(SUM(b.WeightedN), 0)",
    };

    /// A field's expression over the cube: the live one, its service and asset-kind columns read from the cube's own row.
    private static string CubeExpr(Field f) => f.Expr.Replace("sm.", "f.", StringComparison.Ordinal).Replace("a.AssetKind", "f.AssetKind", StringComparison.Ordinal);

    /// <paramref name="cube"/>: null = the live read of the findings; false / true = the stored cube with every finding /
    /// without the exempted ones.
    private static SqlQuery Compose(PivotRequest q, string collectionId, bool cmdb, RowVisibility? visibility, int max, bool? cube, LifecycleFilter? lifecycle = null)
    {
        // #855: the cube's cells and the finding rows carry the CI lifecycle (a key of the cube: distinct assets add up)
        var life = lifecycle is null ? "" : " AND " + lifecycle.Sql("f.CiLifecycle");
        var used = q.Rows.Concat(q.Columns).Concat(q.Filters).Distinct(StringComparer.Ordinal).Select(F).ToList();
        var measures = q.Values.Select(M).ToList();
        var sb = new StringBuilder("WITH ");
        if (used.Any(f => f.Cmdb)) sb.Append((cmdb ? WeightedServiceSql.Cmdb : WeightedServiceSql.NoCmdb).Trim()).Append(",\n");
        sb.Append("b AS (\n    SELECT ");
        if (cube is { } excluding)
        {
            foreach (var f in used) sb.Append(CubeExpr(f)).Append(" AS [").Append(f.Key).Append("], ");
            sb.Append("f.AssetKey, f.Findings AS NFind, f.RiskSum, f.WeightedSum, f.WeightedMax, f.WeightedN\n    FROM sidata.PivotCell AS f\n");
            if (used.Any(f => f.Cmdb)) sb.Append("    LEFT JOIN crit ON crit.K = f.ServiceKey\n");
            if (used.Any(f => f.Department)) sb.Append("    LEFT JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId\n");
            sb.Append("    WHERE ").Append(CollectionViewSql.ThisCollection).Append(life);
            // a pivot without a service field reads each finding group once; with one, once per service of its CI (as the join)
            if (!used.Any(f => f.Service)) sb.Append(" AND f.ServicePrimary = 1");
            if (excluding) sb.Append(" AND f.Exempted = 0");
            sb.Append("\n)\n");
        }
        else
        {
            foreach (var f in used) sb.Append(f.Expr).Append(" AS [").Append(f.Key).Append("], ");
            sb.Append("f.AssetKey, f.RiskScore, f.RiskScoreWeighted\n    FROM sidata.Finding AS f\n");
            if (used.Any(f => f.Asset)) sb.Append("    LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey\n");
            if (used.Any(f => f.Service)) sb.Append("    LEFT JOIN sidata.ServiceMember AS sm ON sm.CollectionId = f.CollectionId AND sm.AssetKey = f.AssetKey\n");
            if (used.Any(f => f.Cmdb)) sb.Append("    LEFT JOIN crit ON crit.K = sm.ServiceKey\n");
            if (used.Any(f => f.Department)) sb.Append("    LEFT JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId\n");
            sb.Append("    WHERE ").Append(CollectionViewSql.ThisCollection).Append(life).Append("\n)\n");
        }

        string Col(string k) => "b.[" + k + "]";
        var dims = q.Rows.Concat(q.Columns).ToList();
        sb.Append("SELECT TOP (@Max) ");
        foreach (var k in dims) sb.Append(Col(k)).Append(" AS [").Append(k).Append("], ");
        sb.Append(q.Rows.Count > 0 ? $"GROUPING({Col(q.Rows[0])})" : "1").Append(" AS GR, ");
        sb.Append(q.Columns.Count > 0 ? $"GROUPING({Col(q.Columns[0])})" : "1").Append(" AS GC");
        foreach (var m in measures) sb.Append(", ").Append(cube is null ? m.Agg : CubeAgg[m.Key]).Append(" AS [M_").Append(m.Key).Append(']');
        sb.Append("\nFROM b\nWHERE 1 = 1");
        foreach (var k in q.FieldsUsed.Where(q.FilterValues.ContainsKey))
            sb.Append("\n  AND ").Append(Col(k)).Append(" IN (SELECT pv.[value] FROM OPENJSON(@").Append(P(k)).Append(") AS pv)");
        if (dims.Count > 0)
        {
            var sets = new List<string>();
            string Set(IEnumerable<string> keys) => "(" + string.Join(", ", keys.Select(Col)) + ")";
            if (q.Rows.Count > 0 && q.Columns.Count > 0) sets.Add(Set(dims));
            if (q.Rows.Count > 0) sets.Add(Set(q.Rows));
            if (q.Columns.Count > 0) sets.Add(Set(q.Columns));
            sets.Add("()");
            sb.Append("\nGROUP BY GROUPING SETS (").Append(string.Join(", ", sets)).Append(')');
            sb.Append("\nORDER BY GR DESC, GC DESC, [M_").Append(measures[0].Key).Append("] DESC");
        }
        sb.Append("\nOPTION (RECOMPILE);");

        var text = sb.ToString();
        var p = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["CollectionId"] = CollectionViewSql.CollectionId(collectionId),
            // one more than shown: a full answer says the pivot was cut
            ["Max"] = Math.Clamp(max, 1, MaxGroups) + 1,
        };
        foreach (var (k, vals) in q.FilterValues) p[P(k)] = JsonSerializer.Serialize(vals);
        if (visibility is not null)
        {
            var cond = CollectionViewSql.ThisCollection + " AND (" + visibility.Sql.Replace("a.AssetKind", DepartmentScope.AssetKindLookup, StringComparison.Ordinal) + ")";
            text = text.Replace(CollectionViewSql.ThisCollection, cond, StringComparison.Ordinal);
            foreach (var kv in visibility.Parameters) p[kv.Key] = kv.Value;
        }
        return new SqlQuery(text, p);
    }

    /// The values one field takes in the collection (a filter's choices), the most findings first.
    public static SqlQuery Choices(string field, string collectionId, bool cmdb, RowVisibility? visibility = null) =>
        Build(ChoicesRequest(field), collectionId, cmdb, visibility, MaxChoices);

    /// The request behind <see cref="Choices"/>: the field down, the findings counted.
    public static PivotRequest ChoicesRequest(string field) =>
        new([F(field).Key], [], ["findings"], [], new Dictionary<string, IReadOnlyList<string>>(), "findings", true);

    /// The fields a database can answer: the Service fields need the services' membership, the Department field the
    /// departments (the CMDB fields read an empty key set without the CMDB, so they stay -- every service reads "not set").
    public static IReadOnlyList<Field> Available(CmdbState s) =>
        Fields.Where(f => (!f.Service || s.HasMembers) && (!f.Department || s.HasDepartments)).ToList();

    // ---- the answer as a table ---------------------------------------------------------------------------------------

    /// <summary>
    /// The grouped rows of <see cref="Build"/> as a pivot table: one line per row-field combination (with its row total),
    /// a column per column-field combination (the largest <see cref="MaxColumnValues"/>, by the first measure's column
    /// total), the column totals and the grand total. Sorted by the request's sort (a criticality, a severity and a tier
    /// in their own order, most critical first).
    /// </summary>
    public static PivotTable Shape(PivotRequest q, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, int max = MaxGroups)
    {
        static string Lab(IReadOnlyDictionary<string, object?> r, string k) =>
            r.TryGetValue(k, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";
        static bool Flag(IReadOnlyDictionary<string, object?> r, string k) =>
            r.TryGetValue(k, out var v) && v is not null && Convert.ToInt32(v, CultureInfo.InvariantCulture) == 1;
        double?[] Vals(IReadOnlyDictionary<string, object?> r) => q.Values.Select(m =>
            r.TryGetValue("M_" + m, out var v) && v is not null ? (double?)Convert.ToDouble(v, CultureInfo.InvariantCulture) : null).ToArray();
        string ColKey(IReadOnlyDictionary<string, object?> r) => string.Join(PivotTable.Join, q.Columns.Select(k => Lab(r, k)));
        string RowKey(IReadOnlyDictionary<string, object?> r) => string.Join("\u001f", q.Rows.Select(k => Lab(r, k)));

        var truncated = rows.Count > max;
        IReadOnlyList<IReadOnlyDictionary<string, object?>> use = truncated ? rows.Take(max).ToList() : rows;
        var hasR = q.Rows.Count > 0; var hasC = q.Columns.Count > 0;
        var grand = new double?[q.Values.Count];
        var colTotals = new Dictionary<string, double?[]>(StringComparer.Ordinal);
        var lines = new Dictionary<string, PivotLine>(StringComparer.Ordinal);
        PivotLine Line(IReadOnlyDictionary<string, object?> r)
        {
            var key = RowKey(r);
            if (!lines.TryGetValue(key, out var l)) lines[key] = l = new PivotLine(q.Rows.Select(k => Lab(r, k)).ToList());
            return l;
        }
        foreach (var r in use)
        {
            var gr = !hasR || Flag(r, "GR"); var gc = !hasC || Flag(r, "GC");
            if (gr && gc) grand = Vals(r);
            else if (gr) colTotals[ColKey(r)] = Vals(r);
            else if (gc) Line(r).Total = Vals(r);
            else Line(r).Cells[ColKey(r)] = Vals(r);
        }
        var cols = colTotals.OrderByDescending(kv => kv.Value.Length > 0 ? kv.Value[0] ?? double.MinValue : double.MinValue)
            .ThenBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => kv.Key).ToList();
        var cut = cols.Count > MaxColumnValues;
        cols = cols.Take(MaxColumnValues).ToList();
        // the columns in their own order where the field has one (criticality, severity, tier), else the largest first
        if (q.Columns.Count == 1) cols = OrderLabels(q.Columns[0], cols).ToList();
        var ordered = Sort(q, lines.Values).ToList();
        return new PivotTable(q, cols, ordered, colTotals, grand, truncated, cut);
    }

    /// The rank a field's value sorts by (lower first), or null when the field sorts alphabetically.
    public static int? LabelRank(string field, string label) => field switch
    {
        "criticality" => label == NoService ? 99 : label == WeightedServiceSql.NotSet ? 98 : WeightedServiceSql.Rank(label) ?? 97,
        "severity" => SeverityOrder.Rank(label),
        "tier" => int.TryParse(label, NumberStyles.None, CultureInfo.InvariantCulture, out var t) ? t : 9,
        "service" or "owner" => label == NoService ? 99 : null,
        _ => null,
    };

    private static IEnumerable<string> OrderLabels(string field, IEnumerable<string> labels) =>
        labels.Select(l => (l, r: LabelRank(field, l))).OrderBy(x => x.r is null ? 0 : 1).ThenBy(x => x.r ?? 0).ThenBy(x => x.r is null ? x.l : "", StringComparer.OrdinalIgnoreCase).Select(x => x.l);

    private static int Idx(IReadOnlyList<string> list, string item)
    {
        for (var i = 0; i < list.Count; i++) if (string.Equals(list[i], item, StringComparison.Ordinal)) return i;
        return -1;
    }

    private static IEnumerable<PivotLine> Sort(PivotRequest q, IEnumerable<PivotLine> lines)
    {
        var s = q.Sort.Split('|', 2);
        var fi = Idx(q.Rows, s[0]);
        if (fi >= 0)
        {
            var key = q.Rows[fi];
            int R(PivotLine l) => LabelRank(key, l.Labels[fi]) ?? 0;
            var o = q.Desc ? lines.OrderByDescending(R).ThenByDescending(l => l.Labels[fi], StringComparer.OrdinalIgnoreCase)
                           : lines.OrderBy(R).ThenBy(l => l.Labels[fi], StringComparer.OrdinalIgnoreCase);
            // within one value of the sort field: the largest first value first (most critical service, then most weighted)
            double First(PivotLine l) => l.Total.Length > 0 && l.Total[0] is { } v ? v : double.MinValue;
            return o.ThenByDescending(First).ThenBy(l => string.Join("\u001f", l.Labels), StringComparer.OrdinalIgnoreCase);
        }
        var mi = Idx(q.Values, s[0]);
        if (mi < 0) mi = 0;
        double? V(PivotLine l) => s.Length > 1 ? (l.Cells.TryGetValue(s[1], out var c) ? c[mi] : null) : l.Total.Length > mi ? l.Total[mi] : null;
        // the first row field's own order breaks ties (most critical first), then the labels
        int R0(PivotLine l) => q.Rows.Count > 0 ? LabelRank(q.Rows[0], l.Labels[0]) ?? 0 : 0;
        var byValue = q.Desc
            ? lines.OrderBy(l => V(l) is null ? 1 : 0).ThenByDescending(l => V(l))
            : lines.OrderBy(l => V(l) is null ? 1 : 0).ThenBy(l => V(l));
        return byValue.ThenBy(R0).ThenBy(l => string.Join("\u001f", l.Labels), StringComparer.OrdinalIgnoreCase);
    }

    /// The default pivot: criticality and service down, the weighted total, findings and assets -- or, without a CMDB,
    /// tier and asset kind down.
    public static PivotRequest Default(bool services) => services
        ? Normalize(["criticality", "service"], [], ["weighted", "findings", "assets"], [], null, "criticality", false)
        : Normalize(["tier", "assetkind"], [], ["weighted", "findings", "assets"], [], null, "tier", false);
}

/// <summary>
/// The pivot builder's moves, as pure functions of a request: what a button (or a drop) changes. Every move answers a NEW
/// request through <see cref="PivotSql.Normalize"/>, so a move can never produce a request the URL could not carry.
/// </summary>
public static class PivotEdit
{
    public const string Rows = "rows";
    public const string Columns = "cols";
    public const string Filters = "filters";
    public const string Values = "values";
    /// Back to the list of fields (removed from every zone).
    public const string Pool = "fields";

    public static readonly IReadOnlyList<string> Zones = [Rows, Columns, Filters, Values];

    private static PivotRequest Make(PivotRequest q, IEnumerable<string> rows, IEnumerable<string> cols, IEnumerable<string> values, IEnumerable<string> filters,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? fv = null)
    {
        var r = rows.ToList(); var c = cols.ToList(); var f = filters.ToList(); var v = values.ToList();
        // the sort stays only where it still names something
        var head = q.Sort.Split('|')[0];
        var sort = r.Contains(head) || v.Contains(head) ? q.Sort : null;
        // a filter's chosen values stay with the field wherever it goes (they keep narrowing the pivot)
        return PivotSql.Normalize(r, c, v, f, fv ?? q.FilterValues, sort, sort is null ? null : q.Desc);
    }

    /// Whether <paramref name="key"/> can go to <paramref name="zone"/> (a field to rows / columns / filters, a measure to
    /// values, anything back to the pool), within the limits.
    public static bool CanMove(PivotRequest q, string key, string zone)
    {
        var measure = PivotSql.MeasureOf(key) is not null;
        var field = PivotSql.FieldOf(key) is not null;
        if (!measure && !field) return false;
        return zone switch
        {
            Pool => measure ? q.Values.Contains(key) && q.Values.Count > 1 : q.FieldsUsed.Contains(key),
            Values => measure && !q.Values.Contains(key) && q.Values.Count < PivotSql.MaxValues,
            Rows => field && !q.Rows.Contains(key) && q.Rows.Count < PivotSql.MaxRows,
            Columns => field && !q.Columns.Contains(key) && q.Columns.Count < PivotSql.MaxColumns,
            Filters => field && !q.Filters.Contains(key) && !q.Rows.Contains(key) && !q.Columns.Contains(key) && q.Filters.Count < PivotSql.MaxFilters,
            _ => false,
        };
    }

    /// <paramref name="key"/> moved to <paramref name="zone"/> (taken out of the zone it was in).
    public static PivotRequest Move(PivotRequest q, string key, string zone)
    {
        if (!CanMove(q, key, zone)) throw new ArgumentException($"'{key}' cannot go to {zone}");
        var k = PivotSql.MeasureOf(key)?.Key ?? PivotSql.FieldOf(key)!.Key;
        IEnumerable<string> Out(IEnumerable<string> z) => z.Where(x => x != k);
        var fv = zone == Pool ? q.FilterValues.Where(x => x.Key != k).ToDictionary(x => x.Key, x => x.Value) : null;
        return zone switch
        {
            Rows => Make(q, Out(q.Rows).Append(k), Out(q.Columns), q.Values, Out(q.Filters)),
            Columns => Make(q, Out(q.Rows), Out(q.Columns).Append(k), q.Values, Out(q.Filters)),
            Filters => Make(q, Out(q.Rows), Out(q.Columns), q.Values, Out(q.Filters).Append(k)),
            Values => Make(q, q.Rows, q.Columns, q.Values.Append(k), q.Filters),
            _ => Make(q, Out(q.Rows), Out(q.Columns), Out(q.Values), Out(q.Filters), fv),
        };
    }

    /// <paramref name="key"/> one place earlier (-1) or later (+1) in its zone; null = it cannot move that way.
    public static PivotRequest? Shift(PivotRequest q, string key, int by)
    {
        static List<string>? Exchange(IReadOnlyList<string> z, string k, int by)
        {
            var l = z.ToList(); var i = l.IndexOf(k); var j = i + by;
            if (i < 0 || j < 0 || j >= l.Count) return null;
            (l[i], l[j]) = (l[j], l[i]);
            return l;
        }
        if (Exchange(q.Rows, key, by) is { } r) return Make(q, r, q.Columns, q.Values, q.Filters);
        if (Exchange(q.Columns, key, by) is { } c) return Make(q, q.Rows, c, q.Values, q.Filters);
        if (Exchange(q.Values, key, by) is { } v) return Make(q, q.Rows, q.Columns, v, q.Filters);
        if (Exchange(q.Filters, key, by) is { } f) return Make(q, q.Rows, q.Columns, q.Values, f);
        return null;
    }

    /// The rows and columns swapped (the dimension turned around).
    public static PivotRequest Swap(PivotRequest q) => Make(q, q.Columns, q.Rows, q.Values, q.Filters);

    /// Sorted by <paramref name="sort"/> (a row field, a measure, or "measure|column"); the same key again flips the direction.
    public static PivotRequest SortBy(PivotRequest q, string sort)
    {
        var desc = string.Equals(q.Sort, sort, StringComparison.Ordinal) ? !q.Desc : PivotSql.MeasureOf(sort.Split('|')[0]) is not null;
        return PivotSql.Normalize(q.Rows, q.Columns, q.Values, q.Filters, q.FilterValues, sort, desc);
    }
}

/// A validated pivot request (<see cref="PivotSql.Normalize"/>).
public sealed record PivotRequest(IReadOnlyList<string> Rows, IReadOnlyList<string> Columns, IReadOnlyList<string> Values, IReadOnlyList<string> Filters,
    IReadOnlyDictionary<string, IReadOnlyList<string>> FilterValues, string Sort, bool Desc)
{
    /// Every field the request uses.
    public IEnumerable<string> FieldsUsed => Rows.Concat(Columns).Concat(Filters).Distinct(StringComparer.Ordinal);

    /// A stable text of everything that shapes the answer (the cache key, a saved view's state).
    public string Shape() => "r=" + string.Join(",", Rows) + "|c=" + string.Join(",", Columns) + "|v=" + string.Join(",", Values) + "|f=" + string.Join(",", Filters) +
        string.Concat(FilterValues.OrderBy(k => k.Key, StringComparer.Ordinal).Select(k => "|" + k.Key + "=" + string.Join("\u001f", k.Value))) + "|s=" + Sort + (Desc ? " d" : " a");

    /// The request as URL parameters (what a link and a saved view carry).
    public IEnumerable<(string Key, string Value)> Query()
    {
        foreach (var r in Rows) yield return ("pr", r);
        foreach (var c in Columns) yield return ("pc", c);
        foreach (var v in Values) yield return ("pv", v);
        foreach (var f in Filters) yield return ("pf", f);
        foreach (var (k, vals) in FilterValues) foreach (var v in vals) yield return ("pfv." + k, v);
        yield return ("psort", Sort);
        yield return ("pdir", Desc ? "desc" : "asc");
    }

    /// The URL query text of <see cref="Query"/>.
    public string QueryString() => string.Join("&", Query().Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value)));

    /// Reads a request back from a query string (a saved view). Unknown keys refused like the URL's.
    public static PivotRequest Parse(string query)
    {
        var parts = query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p =>
        {
            var i = p.IndexOf('=');
            return i < 0 ? (Uri.UnescapeDataString(p), "") : (Uri.UnescapeDataString(p[..i]), Uri.UnescapeDataString(p[(i + 1)..]));
        }).ToList();
        IEnumerable<string?> All(string k) => parts.Where(x => x.Item1 == k).Select(x => (string?)x.Item2);
        var fv = parts.Where(x => x.Item1.StartsWith("pfv.", StringComparison.Ordinal)).GroupBy(x => x.Item1[4..])
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(x => x.Item2).ToList());
        var dir = All("pdir").FirstOrDefault();
        return PivotSql.Normalize(All("pr"), All("pc"), All("pv"), All("pf"), fv, All("psort").FirstOrDefault(), dir is "desc" ? true : dir is "asc" ? false : null);
    }
}

/// One line of the pivot: its row labels, its cells per column key, its row total.
public sealed class PivotLine(IReadOnlyList<string> labels)
{
    public IReadOnlyList<string> Labels { get; } = labels;
    public Dictionary<string, double?[]> Cells { get; } = new(StringComparer.Ordinal);
    public double?[] Total { get; set; } = [];
}

/// The pivot as a table (<see cref="PivotSql.Shape"/>).
public sealed record PivotTable(PivotRequest Request, IReadOnlyList<string> ColumnKeys, IReadOnlyList<PivotLine> Lines,
    IReadOnlyDictionary<string, double?[]> ColumnTotals, double?[] Grand, bool Truncated, bool ColumnsCut)
{
    /// Joins the labels of several column fields into one column key.
    public const string Join = " · ";
}
