using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// One data-model row of the Risk factors page: the shipped template body (null = the customer's own item) and the
/// customer's override (state + body), keyed as cfg.Template / cfg.ItemOverride key it ('risk-factors:&lt;id&gt;',
/// 'mappings/&lt;provider&gt;:&lt;field|recordTypes|resourceTypes&gt;').
public sealed record DataModelRow(string ItemKey, string? TemplateBody, string? TemplateVersion, string? State, string? OverrideBody)
{
    public bool Own => TemplateBody is null;
    public bool Disabled => State == ItemOverrideRepository.StateDisable;
    public bool Overridden => State == ItemOverrideRepository.StateOverride;
    /// The body in force: the override's when there is one, else the template's (null when switched off).
    public string? Effective => Disabled ? null : Overridden ? OverrideBody : TemplateBody;
    public string Template => DataModelItemValidator.Split(ItemKey).Name;
    public string Item => DataModelItemValidator.Split(ItemKey).Item;
}

/// One account the CI build classified as break glass: its CI, name, sign-in name and tier, the sentence that says which
/// rule(s) made it break glass, and the attribute entry ("attribute=value") the identity collection found on it ("" = none).
public sealed record BreakGlassAccount(string CiId, string Name, string Upn, int? Tier, string Reason, string Attribute)
{
    /// "Tier 0" / "Unclassified" -- the one tier wording of every page.
    public string TierText => Tier is >= 0 and <= 3 ? "Tier " + Tier : "Unclassified";
}

/// One risk factor as the page shows it (parsed from the body in force, else the template's).
/// The risk factor model fields (shortName, group, class, impact 1-5, state) are read defensively: a catalog that does
/// not carry them yet shows the id as short name, no group, built-in (the safe reading: it cannot be switched off from
/// here), the impact number as written, and enabled.
public sealed record RiskFactorView(DataModelRow Row, string Id, string Name, string Scope, string Axis, string Stage, string Impact, string Description,
    IReadOnlyList<(string Provider, string Fields)> Providers, bool CiColumn)
{
    /// The report / Excel / PDF name (shortName), else the id in PascalCase.
    public string ShortName { get; init; } = RiskFactorModel.ShortNameOf(Id);
    public string Group { get; init; } = "";
    /// builtin | optional (the SHIPPED item decides; see <see cref="RiskFactorModel.ShippedClass"/>).
    public string Class { get; init; } = RiskFactorModel.Builtin;
    /// enabled | disabled (the factor's own state field; a factor switched off as an item counts as disabled).
    public string State { get; init; } = RiskFactorModel.Enabled;
    /// The impact as a whole number 1-5, or null when it is missing or outside the scale.
    public int? ImpactLevel { get; init; }
    /// The criteria wizard kind (list / threshold / range), or "" when the factor has none.
    public string CriteriaKind { get; init; } = "";
    public bool IsBuiltin => Class != RiskFactorModel.Optional;
    public bool IsEnabled => State != RiskFactorModel.Disabled && !Row.Disabled;
    /// "Asset" or "Vulnerability" -- what the factor is about (appliesTo asset | finding).
    public string About => Scope == "finding" ? "Vulnerability" : Scope == "asset" ? "Asset" : Scope;
}

/// <summary>
/// #527 (4): reads the risk factors and the provider mappings of the Pro data model IN SQL -- the 'datamodel' cfg.Template
/// rows the release publishes (engine\pro-settings\SI-DataModelTemplateRows.ps1) with the customer's cfg.ItemOverride rows
/// (override / disable, and the customer's own items). Writes go through ChangeService.NewDataModelItemAsync (Review &amp;
/// commit) into cfg.ItemOverride; nothing here writes. No custom files in Pro.
/// </summary>
public sealed class RiskFactorStore
{
    public const string MissingSchemaMessage = "This database has no data-model templates yet (cfg.Template / cfg.ItemOverride) -- they arrive with the next update of the Pro settings schema and templates.";

    public const string ListSql = """
IF OBJECT_ID(N'cfg.Template') IS NOT NULL AND OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL
SELECT x.ItemKey, x.TemplateBody, x.TemplateVersion, x.State, x.OverrideBody FROM (
    SELECT t.ItemKey, t.BodyJson AS TemplateBody, t.[Version] AS TemplateVersion, o.State, o.BodyJson AS OverrideBody, t.SortOrder AS Ord
    FROM cfg.Template t
    LEFT JOIN cfg.ItemOverride o ON o.Kind = t.Kind AND o.ItemKey = t.ItemKey
    WHERE t.Kind = N'datamodel' AND t.RetiredAt IS NULL AND (t.ItemKey LIKE N'risk-factors:%' OR t.ItemKey LIKE N'mappings/%' OR t.ItemKey LIKE N'lists:%' OR t.ItemKey LIKE N'recommendation-equivalence:%' OR t.ItemKey = N'report-scope' OR t.ItemKey LIKE N'report-scope:%' OR t.ItemKey LIKE N'dimensions:%' OR t.ItemKey LIKE N'classification:%' OR t.ItemKey = N'classification')
    UNION ALL
    SELECT o.ItemKey, NULL, NULL, o.State, o.BodyJson, 2147483647
    FROM cfg.ItemOverride o
    WHERE o.Kind = N'datamodel' AND (o.ItemKey LIKE N'risk-factors:%' OR o.ItemKey LIKE N'mappings/%' OR o.ItemKey LIKE N'lists:%' OR o.ItemKey LIKE N'recommendation-equivalence:%' OR o.ItemKey LIKE N'report-scope:%' OR o.ItemKey LIKE N'dimensions:%' OR o.ItemKey LIKE N'classification:%')
      AND NOT EXISTS (SELECT 1 FROM cfg.Template t WHERE t.Kind = o.Kind AND t.ItemKey = o.ItemKey AND t.RetiredAt IS NULL)
) x
ORDER BY x.Ord, x.ItemKey;
""";

    /// The values SI collected for a criteria field (and its detail field), most common first -- what the list wizard's
    /// dropdowns offer. Read from the CI documents (sidata.Ci); the field names are validated SI field names (^si_[a-z0-9_]+$),
    /// so they are safe inside the JSON path.
    public static string CollectedSql(string field, string? detail)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(field, "^si_[a-z0-9_]+$") || (detail is { Length: > 0 } && !System.Text.RegularExpressions.Regex.IsMatch(detail, "^si_[a-z0-9_]+$")))
            throw new ArgumentException("not an SI field name");
        var d = string.IsNullOrEmpty(detail) ? "CAST(NULL AS nvarchar(256))" : $"JSON_VALUE(DocJson, '$.{detail}')";
        return $"""
IF OBJECT_ID(N'sidata.Ci') IS NOT NULL
SELECT TOP (500) x.V, x.D, COUNT_BIG(*) AS N FROM (
    SELECT JSON_VALUE(DocJson, '$.{field}') AS V, {d} AS D
    FROM sidata.Ci
    WHERE DocJson IS NOT NULL AND ISJSON(DocJson) = 1 AND ISNULL(Lifecycle, N'') <> N'retired'
) x
WHERE x.V IS NOT NULL AND x.V <> N''
GROUP BY x.V, x.D
ORDER BY COUNT_BIG(*) DESC, x.V, x.D;
""";
    }

    /// The values SI collected for a FINDING field, most common first -- the Dimensions rule wizard's dropdown for a rule
    /// over a finding (read from the CI findings, sidata.CiFinding). Same field-name guard as <see cref="CollectedSql"/>.
    public static string CollectedFindingSql(string field)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(field, "^si_[a-z0-9_]+$")) throw new ArgumentException("not an SI field name");
        return $"""
IF OBJECT_ID(N'sidata.CiFinding') IS NOT NULL
SELECT TOP (500) x.V, CAST(NULL AS nvarchar(256)) AS D, COUNT_BIG(*) AS N FROM (
    SELECT JSON_VALUE(DocJson, '$.{field}') AS V
    FROM sidata.CiFinding
    WHERE DocJson IS NOT NULL AND ISJSON(DocJson) = 1
) x
WHERE x.V IS NOT NULL AND x.V <> N''
GROUP BY x.V
ORDER BY COUNT_BIG(*) DESC, x.V;
""";
    }

    /// The collected values of a field for a dimension rule: an asset field from the CIs, a finding field from the findings.
    public async Task<IReadOnlyList<FactorCriteria.Collected>> CollectedForAsync(string field, string subject, CancellationToken ct)
    {
        if (subject != "finding") return await CollectedAsync(field, null, ct);
        var rows = await _sql.QueryAsync(CollectedFindingSql(field), new Dictionary<string, object?>(), ct);
        return rows.Where(r => !string.IsNullOrEmpty(r.Str("V"))).Select(r => new FactorCriteria.Collected(r.Str("V")!, null, r.Long("N") ?? 0)).ToList();
    }

    /// The collected values as wizard choices: each value with "any detail" plus each value + detail pair seen.
    public async Task<IReadOnlyList<FactorCriteria.Collected>> CollectedAsync(string field, string? detail, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(CollectedSql(field, detail), new Dictionary<string, object?>(), ct);
        var list = new List<FactorCriteria.Collected>();
        foreach (var g in rows.GroupBy(r => r.Str("V") ?? "", StringComparer.Ordinal).Where(g => g.Key.Length > 0))
        {
            list.Add(new FactorCriteria.Collected(g.Key, null, g.Sum(r => r.Long("N") ?? 0)));
            if (!string.IsNullOrEmpty(detail))
                foreach (var r in g.Where(r => !string.IsNullOrEmpty(r.Str("D")))) list.Add(new FactorCriteria.Collected(g.Key, r.Str("D"), r.Long("N") ?? 0));
        }
        return list;
    }
    // ---- the break glass accounts (Risk factors > Break glass) -----------------------------------------------------------

    /// How many break glass accounts the page lists at most (a tenant has a handful; more is said, never cut silently).
    public const int BreakGlassTop = 500;

    /// Whether this database holds the two prepared columns the list is read from (0 / 1). They arrive with the data
    /// schema of this version and are filled by the data sync (ProData/DataModel/view-stored-columns.json).
    public const string BreakGlassReadySql = """
SELECT CASE WHEN OBJECT_ID(N'sidata.Ci') IS NOT NULL
             AND COL_LENGTH(N'sidata.Ci', N'BreakGlassReason') IS NOT NULL
             AND COL_LENGTH(N'sidata.Ci', N'BreakGlassAttribute') IS NOT NULL
             AND COL_LENGTH(N'sidata.Ci', N'Upn') IS NOT NULL
            THEN 1 ELSE 0 END AS Ready;
""";

    /// The accounts the CI build classified as break glass, each with WHY (the rule or rules that matched, in one
    /// sentence) and the attribute entry it carries. Read from the prepared columns only: the reason is set on a break
    /// glass account and on no other, so "has a reason" is the whole test and the index on it (IX_Ci_BreakGlassReason)
    /// answers it -- the page never opens a CI document and never walks the identities.
    public const string BreakGlassAccountsSql = """
SELECT TOP (@Top) c.CiId, c.Name, c.Upn, c.Tier, c.BreakGlassReason, c.BreakGlassAttribute
FROM sidata.Ci AS c
WHERE c.BreakGlassReason > N'' AND ISNULL(c.Lifecycle, N'') <> N'retired'
ORDER BY c.Name, c.CiId;
""";

    /// The break glass accounts as of the last data sync; null when this database does not hold the prepared columns yet.
    /// One more than <see cref="BreakGlassTop"/> is asked for, so the page can say that there are more.
    public async Task<IReadOnlyList<BreakGlassAccount>?> BreakGlassAccountsAsync(CancellationToken ct)
    {
        SI.Management.Core.SqlGuard.AssertReadOnly(BreakGlassReadySql);
        var ready = await _sql.QueryAsync(BreakGlassReadySql, new Dictionary<string, object?>(), ct);
        if (ready.Count == 0 || !ready[0].ContainsKey("Ready") || ready[0].Long("Ready") != 1) return null;
        SI.Management.Core.SqlGuard.AssertReadOnly(BreakGlassAccountsSql);
        var rows = await _sql.QueryAsync(BreakGlassAccountsSql, new Dictionary<string, object?> { ["Top"] = BreakGlassTop + 1 }, ct);
        return rows.Where(r => !string.IsNullOrEmpty(r.Str("CiId")))
            .Select(r => new BreakGlassAccount(r.Str("CiId")!, r.Str("Name") ?? "", r.Str("Upn") ?? "", (int?)r.Long("Tier"), r.Str("BreakGlassReason") ?? "", r.Str("BreakGlassAttribute") ?? ""))
            .ToList();
    }

    private readonly ISqlExecutor _sql;
    public RiskFactorStore(ISqlExecutor sql) => _sql = sql;

    /// Every factor and mapping row; null when the schema is not there yet.
    public async Task<IReadOnlyList<DataModelRow>?> ListAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct);
        if (rows.Count == 0) return null;
        return rows.Select(r => new DataModelRow(r.Str("ItemKey") ?? "", r.Str("TemplateBody"), r.Str("TemplateVersion"), r.Str("State"), r.Str("OverrideBody"))).ToList();
    }

    /// PURE. The risk rating bands in force: the list risk_rating_bands (the customer's override included); the built-in
    /// 50 / 30 / 15 when the list is missing, switched off or not valid -- as the engine does (ConvertTo-RARiskRatingBands).
    public static SI.Management.Core.ProData.RiskRatingBands Bands(IEnumerable<DataModelRow> rows) =>
        SI.Management.Core.ProData.RiskRatingBands.FromList(rows.FirstOrDefault(r => r.ItemKey == SI.Management.Core.ProData.RiskRatingBands.ItemKey)?.Effective)
        ?? SI.Management.Core.ProData.RiskRatingBands.Default;

    /// The bands in force, read from the Pro database (the built-in ones when it cannot be read).
    public async Task<SI.Management.Core.ProData.RiskRatingBands> BandsAsync(CancellationToken ct)
    {
        try { return await ListAsync(ct) is { } rows ? Bands(rows) : SI.Management.Core.ProData.RiskRatingBands.Default; }
        catch (Exception ex) when (ex is not OperationCanceledException) { return SI.Management.Core.ProData.RiskRatingBands.Default; }
    }

    /// PURE. The factors of a row list, parsed for display (an unreadable body shows its key only).
    public static IReadOnlyList<RiskFactorView> Factors(IEnumerable<DataModelRow> rows) =>
        rows.Where(r => r.Template == "risk-factors" && r.Item.Length > 0).Select(View).ToList();

    /// PURE. The provider mappings, per provider: (provider, SI field, source paths, the row).
    public static IReadOnlyList<(string Provider, string Field, string Sources, DataModelRow Row)> Mappings(IEnumerable<DataModelRow> rows)
    {
        var list = new List<(string, string, string, DataModelRow)>();
        foreach (var r in rows.Where(r => r.Template.StartsWith("mappings/", StringComparison.Ordinal) && r.Item.Length > 0))
        {
            var prov = r.Template["mappings/".Length..];
            string field = r.Item.Split('|')[0], sources = "";
            try
            {
                using var d = JsonDocument.Parse(r.Effective ?? r.TemplateBody ?? r.OverrideBody ?? "{}");
                if (d.RootElement.TryGetProperty("field", out var f) && f.ValueKind == JsonValueKind.String) field = f.GetString() ?? field;
                if (d.RootElement.TryGetProperty("sources", out var s) && s.ValueKind == JsonValueKind.Array) sources = string.Join(", ", s.EnumerateArray().Select(x => x.ToString()));
            }
            catch (JsonException) { }
            list.Add((prov, field, sources, r));
        }
        return list;
    }

    /// PURE. #464 the recommendation equivalence groups: (canonical title, canonical id, "provider: id or title" per member, stage, the row).
    public static IReadOnlyList<(string Title, string CanonicalId, IReadOnlyList<string> Members, string Stage, DataModelRow Row)> Equivalences(IEnumerable<DataModelRow> rows)
    {
        var list = new List<(string, string, IReadOnlyList<string>, string, DataModelRow)>();
        foreach (var r in rows.Where(r => r.Template == "recommendation-equivalence" && r.Item.Length > 0))
        {
            string title = r.Item, cid = "", stage = "production"; var members = new List<string>();
            try
            {
                using var d = JsonDocument.Parse(r.Effective ?? r.TemplateBody ?? r.OverrideBody ?? "{}");
                var o = d.RootElement;
                // #693 an operator's link of findings is shown on the findings' own pages, not here
                if (S(o, "match") == "link") continue;
                // #693 a meaning rule (fold): its description names it; its conditions are shown as its members
                if (S(o, "match") == "fold")
                {
                    if (S(o, "description") is { Length: > 0 } desc) title = r.Item + " -- " + desc;
                    cid = "(meaning rule)";
                    foreach (var (side, label) in new[] { ("evidence", "becomes evidence: "), ("canonical", "stays: ") })
                        if (o.TryGetProperty(side, out var cs) && cs.ValueKind == JsonValueKind.Array)
                            foreach (var c in cs.EnumerateArray()) members.Add(label + S(c, "field") + (S(c, "pattern") is { Length: > 0 } p ? " ~ " + p : " = " + S(c, "equals")));
                    if (S(o, "stage") is { Length: > 0 } fst) stage = fst;
                    list.Add((title, cid, members, stage, r));
                    continue;
                }
                if (S(o, "canonicalTitle") is { Length: > 0 } t) title = t;
                cid = S(o, "canonicalId");
                if (S(o, "stage") is { Length: > 0 } st) stage = st;
                if (o.TryGetProperty("members", out var m) && m.ValueKind == JsonValueKind.Array)
                    foreach (var x in m.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object))
                        members.Add(S(x, "provider") + ": " + (S(x, "id") is { Length: > 0 } id ? id : "\"" + S(x, "title") + "\""));
            }
            catch (JsonException) { }
            list.Add((title, cid, members, stage, r));
        }
        return list;
    }

    /// <summary>
    /// PURE. #693 THE PROMOTION SWITCH: a meaning rule (match "fold") shipped at stage "testing" made live -- the body in
    /// force with ONLY its stage set to "production" (no code: one data-model override, staged on Review &amp; commit like
    /// every other). Refused for anything that is not a fold rule at stage testing. The engine folds with it from the next
    /// Risk Analysis run; "put the shipped one back" (inherit) is the way back to testing.
    /// </summary>
    public static (string? Body, string? Why) PromoteFold(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return (null, "the rule has no body");
        try
        {
            var n = System.Text.Json.Nodes.JsonNode.Parse(body) as System.Text.Json.Nodes.JsonObject;
            if (n is null) return (null, "the rule is not a JSON object");
            if ((string?)n["match"] != "fold") return (null, "only a meaning rule (match fold) is promoted this way");
            if ((string?)n["stage"] != "testing") return (null, $"the rule is at stage '{(string?)n["stage"] ?? "production"}', not testing -- nothing to promote");
            n["stage"] = "production";
            return (n.ToJsonString(), null);
        }
        catch (JsonException ex) { return (null, "the rule's body is not valid JSON: " + ex.Message); }
        catch (InvalidOperationException) { return (null, "the rule's match / stage is not text"); }
    }

    private static string S(JsonElement o, string p) => o.TryGetProperty(p, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString() : "";

    private static RiskFactorView View(DataModelRow r)
    {
        var body = r.Effective ?? r.TemplateBody ?? r.OverrideBody;
        try
        {
            using var d = JsonDocument.Parse(body ?? "{}");
            var o = d.RootElement;
            var provs = new List<(string, string)>();
            if (o.TryGetProperty("providers", out var p) && p.ValueKind == JsonValueKind.Object)
                foreach (var prop in p.EnumerateObject())
                {
                    var fields = prop.Value.ValueKind == JsonValueKind.Array
                        ? prop.Value.EnumerateArray().Select(x => x.TryGetProperty("sources", out var src) && src.ValueKind == JsonValueKind.Array ? string.Join(", ", src.EnumerateArray().Select(y => y.ToString())) : x.TryGetProperty("list", out var l) ? "list " + l.GetString() : "").Where(x => x.Length > 0)
                        : Array.Empty<string>();
                    provs.Add((prop.Name, string.Join("; ", fields)));
                }
            var ci = o.TryGetProperty("ciColumn", out var c) && c.ValueKind == JsonValueKind.True;
            var fid = S(o, "id") is { Length: > 0 } id ? id : r.Item;
            return new RiskFactorView(r, fid, S(o, "name"), S(o, "appliesTo"), S(o, "axis"), S(o, "stage"), S(o, "impact"), S(o, "description"), provs, ci)
            {
                ShortName = S(o, "shortName") is { Length: > 0 } sn ? sn : RiskFactorModel.ShortNameOf(fid),
                Group = S(o, "group"),
                Class = RiskFactorModel.ShippedClass(r),
                State = S(o, "state") == RiskFactorModel.Disabled ? RiskFactorModel.Disabled : RiskFactorModel.Enabled,
                ImpactLevel = RiskFactorModel.ImpactOf(o),
                CriteriaKind = FactorCriteria.Of(o)?.Kind ?? "",
            };
        }
        catch (JsonException) { return new RiskFactorView(r, r.Item, "", "", "", "", "", "", Array.Empty<(string, string)>(), false); }
    }
}
