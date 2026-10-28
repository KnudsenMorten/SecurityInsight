namespace SI.Management.Core.ProData;

/// <summary>
/// The rows a signed-in user may SEE, as an extra WHERE predicate on the finding queries (#253). Built from the user's
/// scopes: ANY of the scopes (OR), each scope = ALL of its constrained columns (AND), each column = one of its values
/// (IN). The text is made only of whitelisted column expressions (<see cref="Columns"/>) and generated parameter names --
/// every value travels as a parameter, so the "constant text, values as parameters" rule of <see cref="ProDataSql"/> holds.
/// A scope type that restricts what its holder sees (a department, #254) adds its column here; a security domain does not
/// restrict visibility (a Delegated user for a domain still sees everything, read-only outside it).
/// </summary>
public sealed record VisibilityPredicate(string Sql, IReadOnlyDictionary<string, object?> Parameters)
{
    /// Scope type -> the column expression over the finding queries' aliases (f = sidata.Finding, a = sidata.Asset).
    public static readonly IReadOnlyDictionary<string, string> Columns = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["domain"] = "f.SecurityDomain",
        ["assetKind"] = "a.AssetKind",
        ["tier"] = ProDataSql.TierExpr("f.Tier"),
        // the department the data sync stamped on the finding (#254); a scope value is a department id
        [DepartmentScope.VisibilityColumn] = DepartmentScope.ColumnSql,
    };

    /// Null = no restriction. An empty list of scopes = sees nothing ("1 = 0"). A column key not in
    /// <see cref="Columns"/> throws (it would otherwise be silently unfiltered).
    public static VisibilityPredicate? Build(IReadOnlyList<IReadOnlyList<(string Column, IReadOnlyList<string> Values)>>? anyOf)
    {
        if (anyOf is null) return null;
        if (anyOf.Count == 0) return new VisibilityPredicate("1 = 0", new Dictionary<string, object?>());
        var p = new Dictionary<string, object?>(StringComparer.Ordinal);
        var ors = new List<string>();
        foreach (var scope in anyOf)
        {
            var ands = new List<string>();
            foreach (var (column, values) in scope)
            {
                if (!Columns.TryGetValue(column, out var expr)) throw new ArgumentException($"'{column}' is not a visibility column");
                if (values.Count == 0) { ands.Add("1 = 0"); continue; }
                var names = new List<string>();
                foreach (var v in values) { var n = "Vis" + p.Count; p[n] = v; names.Add("@" + n); }
                ands.Add($"{expr} IN ({string.Join(", ", names)})");
            }
            ors.Add(ands.Count == 0 ? "1 = 1" : "(" + string.Join(" AND ", ands) + ")");
        }
        return new VisibilityPredicate(string.Join(" OR ", ors), p);
    }
}
