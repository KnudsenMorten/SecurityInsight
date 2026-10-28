using System.Globalization;
using System.Security.Claims;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Tasks;

using Fmt = SI.Management.Web.Pages.Fmt;

namespace SI.Management.Web.Actions;

/// Where a selection was made: the findings browser, a collection grid of finding rows (raw rows, a CI's findings, the
/// facet views), or a department grid (a department's findings, the Unassigned queue).
public static class SelectionSources
{
    public const string Findings = "findings";
    public const string Rows = "rows";
    public const string Department = "department";
    public static readonly IReadOnlyList<string> All = [Findings, Rows, Department];
}

/// <summary>
/// WHAT a request to <c>/Actions/Apply</c> acts on, as the browser sent it: the source, the collection, the selected
/// finding ids (keys (CollectionId, FindingId)) -- or "all matching" plus the filter. Only these KEYS travel; the findings
/// are always read again on the server (<see cref="FindingSelectionResolver"/>), never trusted from the form.
/// </summary>
public sealed record FindingSelection(string Source, string? CollectionId, IReadOnlyList<string> Ids, bool All,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Origin)
{
    /// The filter fields an "all matching" request carries (the findings browser's, the grids' f.* / q / key, the
    /// department page's id / unassigned, the #264 tick).
    /// The longest row key of an aggregated grid that is read (a CI id of 64, a '|', an asset id or a finding key...).
    public const int MaxRowKey = 1024;

    public static readonly IReadOnlyList<string> OriginKeys =["tier", "sev", "dom", "rep", "kind", "q", "key", "id", "unassigned", "svc", "a", Exempted.QueryKey];

    public string? Get(string k) => Origin.TryGetValue(k, out var v) && v.Count > 0 && !string.IsNullOrWhiteSpace(v[0]) ? v[0].Trim() : null;

    /// #391: the department whose OWN page the selection was made on (a department's findings grid -- not the Unassigned
    /// queue, not any other grid). The resolver reads the findings from exactly that department's grid, under the user's
    /// visibility, so a selection with this context holds only that department's findings.
    public int? DepartmentContext => Source == SelectionSources.Department && Get("unassigned") != "1"
        && int.TryParse(Get("id"), NumberStyles.None, CultureInfo.InvariantCulture, out var d) && d > 0 ? d : null;

    public static FindingSelection From(IFormCollection form)
    {
        var src = form["src"].ToString().Trim().ToLowerInvariant();
        if (!SelectionSources.All.Contains(src)) src = SelectionSources.Findings;
        var c = form["c"].ToString().Trim();
        var grid = form["grid"].ToString().Trim();
        // a finding id fits 64 characters; an aggregated grid's row key is longer (a CI id and a finding key, a CMDB group...)
        var maxKey = src == SelectionSources.Rows && FindingRowMaps.Of(grid) is { Aggregated: true } ? MaxRowKey : 64;
        var ids = form["sel"].Where(v => !string.IsNullOrWhiteSpace(v) && v!.Length <= maxKey).Select(v => v!.Trim()).Distinct(StringComparer.Ordinal).ToList();
        var origin = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in form)
        {
            var k = kv.Key;
            if (!(OriginKeys.Contains(k, StringComparer.OrdinalIgnoreCase) || k.StartsWith("f.", StringComparison.OrdinalIgnoreCase))) continue;
            var vals = kv.Value.Where(v => !string.IsNullOrWhiteSpace(v) && v!.Length <= 400).Select(v => v!).ToList();
            if (vals.Count > 0) origin[k] = vals;
        }
        return new FindingSelection(src, c.Length == 0 ? null : c, ids, form["all"] == "1", origin)
        {
            Grid = grid.Length is > 0 and <= 64 && System.Text.RegularExpressions.Regex.IsMatch(grid, "^[A-Za-z0-9@_-]+$") ? grid : null,
        };
    }

    /// #286: the grid the rows were selected on (its spec name). An aggregated grid's keys are its rows' keys (a CVE, a
    /// CI, a service...), each standing for the findings its <see cref="FindingRowMap"/> declares.
    public string? Grid { get; init; }

    /// The row-to-finding mapping of the grid (null = the rows are findings: the findings browser, raw rows).
    public FindingRowMap? Map => Source == SelectionSources.Rows && FindingRowMaps.Of(Grid) is { } m && (m.Aggregated || !m.Acts) ? m : null;

    /// The grid's column filters (f.&lt;column&gt;, several values joined with '|').
    public IReadOnlyDictionary<string, string> GridFilters => Origin.Where(kv => kv.Key.StartsWith("f.", StringComparison.OrdinalIgnoreCase))
        .ToDictionary(kv => kv.Key[2..], kv => string.Join("|", kv.Value), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The filter narrows the collection (#264): the findings browser's filters, a grid's column filter / search / one CI,
    /// or a department page (a department, or the Unassigned queue, is a slice of the collection, never the whole of it).
    /// </summary>
    public bool Narrowed => Source switch
    {
        SelectionSources.Findings => ExemptionBulkGuard.Narrows(Get("tier"), Get("sev"), Get("dom"), Get("rep"), Get("kind"), Get("q")),
        SelectionSources.Department => true,
        _ => GridFilters.Count > 0 || Get("q") is not null || Get("key") is not null || Get("svc") is not null,
    };
}

/// What the server read back: the findings (each with its department), how many the filter matched, the selected keys
/// that are not (or no longer) there, and the reason nothing can be done (null = go on).
public sealed record ResolvedSelection(IReadOnlyList<GovernanceTarget> Targets, long Matching, IReadOnlyList<FindingActionResult> Missing, string? Error)
{
    /// #286: the aggregated rows the selection was made of (null = the rows were findings), and what they are.
    public long? Rows { get; init; }
    public string? RowNoun { get; init; }

    /// "2 CVE rows = 5 findings" (the viewer's number format); null for a selection of findings.
    public string? Expansion => Rows is { } n ? $"{Fmt.Int(n)} {RowNoun} row(s) = {Fmt.Int(Targets.Count)} finding(s)" : null;

    public static ResolvedSelection Fail(string why, long matching = 0) => new(Array.Empty<GovernanceTarget>(), matching, Array.Empty<FindingActionResult>(), why);
}

/// <summary>
/// Reads a <see cref="FindingSelection"/> back from the Pro database: the selected keys one by one (the findings browser)
/// or in ONE grid read (the collection and department grids), "all matching" by the same filter the page applied --
/// under the user's department visibility (#253 x #254) and the #264 bulk guard (a narrowing filter, at most
/// SIWeb_Exemption_BulkMax findings, and at most the action's own limit). Each finding gets its department (the data
/// sync's stamp), which is what the per-finding permission checks need.
/// </summary>
public sealed class FindingSelectionResolver
{
    private readonly IProDataQueries _q;
    private readonly ICollectionViews _views;
    private readonly FindingThreadService _threads;
    private readonly IDepartmentScopeResolver _scope;
    private readonly IAccessScope _access;
    private readonly ExemptionSettings _settings;
    private readonly IExemptedSchema? _exempted;
    private readonly ILogger<FindingSelectionResolver> _log;
    private readonly SI.Management.Web.Guards.GuardEventWriter? _guards;
    private readonly ICiViews? _cis;
    private readonly SI.Management.Web.Guards.GuardModeReader? _guardMode;

    public FindingSelectionResolver(IProDataQueries q, ICollectionViews views, FindingThreadService threads, IDepartmentScopeResolver scope, IAccessScope access,
        ExemptionSettings settings, ILogger<FindingSelectionResolver> log, IExemptedSchema? exempted = null, SI.Management.Web.Guards.GuardEventWriter? guards = null,
        ICiViews? cis = null, SI.Management.Web.Guards.GuardModeReader? guardMode = null)
    { _q = q; _views = views; _threads = threads; _scope = scope; _access = access; _settings = settings; _log = log; _exempted = exempted; _guards = guards; _cis = cis; _guardMode = guardMode; }

    /// #277: a refusal of the bulk guard (no narrowing filter, or more findings than the limit) is a guard event -- mailed
    /// and reported by the mail job. Never fails the request.
    private async Task GuardAsync(IFindingAction action, bool narrowed, long matching, int max, string reason, CancellationToken ct)
    {
        if (_guards is null) return;
        // CR4 (#654): in the stricter period the event carries the configured limit beside the halved one
        double? configured = null;
        if (_guardMode is not null && (await _guardMode.ReadAsync(ct)).IsStrict)
        {
            var c = Math.Min(await ConfiguredBulkMaxAsync(ct), action.BulkLimit);
            if (c != max) configured = c;
        }
        await _guards.WriteAsync("exemption.bulk.refused", "refused", action.Label, reason,
            [new SI.Management.Web.Guards.GuardValue("findingsMatching", "Findings matching the request", narrowed ? matching : null, max) { Configured = configured },
             new SI.Management.Web.Guards.GuardValue("filterNarrows", "The filter narrows the collection (1 = yes)", narrowed ? 1 : 0, 1)], 0, ct);
    }

    private async Task<int> ConfiguredBulkMaxAsync(CancellationToken ct)
    {
        try { return (await _settings.ReadAsync(ct)).BulkMax; }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "exemption settings"); return ExemptionSettings.Values.Defaults.BulkMax; }
    }

    /// SIWeb_Exemption_BulkMax (the #264 guard of every "all matching") -- halved for 24 hours after a release that changed
    /// engine code (CR4, GuardModeRules: the configured value x 0.5, at least 1).
    public async Task<int> BulkMaxAsync(CancellationToken ct)
    {
        var configured = await ConfiguredBulkMaxAsync(ct);
        if (_guardMode is null) return configured;
        var mode = await _guardMode.ReadAsync(ct);
        return (int)SI.Management.Web.Guards.GuardModeRules.Effective(configured, mode);
    }

    /// The guard of "all matching" for one action: the action must allow it, the filter must narrow the collection, and
    /// the matching findings must be at most the smaller of the setting and the action's limit.
    public static ExemptionBulkGuard.Verdict Guard(IFindingAction action, bool narrowed, long matching, int bulkMax)
    {
        if (!action.SupportsAllMatching) return new(false, $"\"{action.Label}\" applies to selected findings only -- select them.");
        return ExemptionBulkGuard.Check(narrowed, matching, Math.Min(bulkMax, action.BulkLimit));
    }

    public async Task<ResolvedSelection> ResolveAsync(ClaimsPrincipal user, FindingSelection sel, IFindingAction action, CancellationToken ct)
    {
        try
        {
            if (sel.CollectionId is not null) ProDataFilters.Id(sel.CollectionId, "collection");
            var access = await _scope.ResolveAsync(user, ct);
            var tick = sel.Get(Exempted.QueryKey);
            var ready = _exempted is not null && await _exempted.ReadyAsync(ct);
            using var _ = Exempted.Use(!ready ? null : tick == "1" ? ExemptedScope.IncludeAll : ExemptedScope.Exclude);

            // #286: rows of an aggregated grid (a CVE, a CI, a service...) stand for the findings their map declares
            if (sel.Map is { } map) return await ResolveRowsAsync(sel, map, action, access, ct);

            IReadOnlyList<FindingRow> rows;
            long matching;
            var missing = new List<FindingActionResult>();
            if (sel.All)
            {
                var bulkMax = await BulkMaxAsync(ct);
                var max = Math.Min(bulkMax, action.BulkLimit);
                if (!action.SupportsAllMatching) return ResolvedSelection.Fail(Guard(action, sel.Narrowed, 0, bulkMax).Reason!);
                if (!sel.Narrowed)
                {
                    var why = Guard(action, false, 0, bulkMax).Reason!;
                    await GuardAsync(action, false, 0, max, why, ct);
                    return ResolvedSelection.Fail(why);
                }
                (rows, matching) = await AllAsync(user, sel, access, max, ct);
                var verdict = Guard(action, true, matching, bulkMax);
                if (!verdict.Allowed)
                {
                    if (matching > max) await GuardAsync(action, true, matching, max, verdict.Reason!, ct);
                    return ResolvedSelection.Fail(verdict.Reason!, matching);
                }
            }
            else
            {
                if (sel.Ids.Count == 0) return ResolvedSelection.Fail("Select at least one finding first.");
                if (sel.Ids.Count > action.BulkLimit)
                    return ResolvedSelection.Fail($"{Fmt.Int(sel.Ids.Count)} findings are selected -- \"{action.Label}\" takes at most {Fmt.Int(action.BulkLimit)} at once. Narrow the selection.", sel.Ids.Count);
                rows = await SelectedAsync(sel, access, ct);
                matching = sel.Ids.Count;
                foreach (var id in sel.Ids.Where(id => rows.All(r => r.FindingId != id)))
                    missing.Add(new FindingActionResult(id, null, null, false, "not in this collection (or not one you may see)"));
            }
            var targets = new List<GovernanceTarget>();
            foreach (var r in rows) targets.Add(await _threads.TargetAsync(r, ct));
            return new ResolvedSelection(targets, matching, missing, targets.Count == 0 && missing.Count == 0 ? "No finding matches." : null);
        }
        catch (ArgumentException ex) { return ResolvedSelection.Fail("The selection is not valid: " + ex.Message); }
    }

    /// <summary>
    /// #286: a selection of AGGREGATED rows (or "all matching" on an aggregated grid) as the findings they stand for in
    /// the collection -- each row through its grid's <see cref="FindingRowMap"/>, the findings read from the collection's
    /// raw rows under the user's department visibility. A row that stands for no finding (one you may not see, a finding
    /// that is gone) is listed as refused with its key. The action's own limit (and, for "all matching", the bulk guard)
    /// applies to the FINDINGS, not to the rows.
    /// </summary>
    private async Task<ResolvedSelection> ResolveRowsAsync(FindingSelection sel, FindingRowMap map, IFindingAction action, DepartmentAccess access, CancellationToken ct)
    {
        string Rows(long n) => $"{Fmt.Int(n)} {map.RowNoun} row(s)";
        if (!map.Acts) return ResolvedSelection.Fail("The rows of this view stand for no finding -- " + map.Describe + ".");
        var cur = await CollectionAsync(sel.CollectionId, ct) ?? throw new ArgumentException("that collection is not in the Pro database");
        var bulkMax = await BulkMaxAsync(ct);
        var max = sel.All ? Math.Min(bulkMax, action.BulkLimit) : action.BulkLimit;
        IReadOnlyList<IReadOnlyDictionary<string, object?>>? read = null;
        List<string> keys;
        if (sel.All)
        {
            if (!action.SupportsAllMatching) return ResolvedSelection.Fail(Guard(action, sel.Narrowed, 0, bulkMax).Reason!);
            if (!map.AllMatching || map.Spec is null || map.Parameters is null)
                return ResolvedSelection.Fail($"\"All matching\" is not offered on this view -- tick the {map.RowNoun} rows to act on.");
            if (!sel.Narrowed)
            {
                var why = Guard(action, false, 0, bulkMax).Reason!;
                await GuardAsync(action, false, 0, max, why, ct);
                return ResolvedSelection.Fail(why);
            }
            var page = (await _views.ExportAsync(new GridQuery(map.Spec, map.Parameters(cur, sel), cur.Version + "|act",
                new GridRequest { Search = sel.Get("q"), Filters = sel.GridFilters.ToDictionary(kv => kv.Key, kv => kv.Value), Size = 50 }), ct)).Data;
            if (page.Total > max)
            {
                var why = $"{Rows(page.Total)} match the filter -- that is more than the {Fmt.Int(max)} findings \"{action.Label}\" may change at once, before they are even counted. Narrow the filter.";
                await GuardAsync(action, true, page.Total, max, why, ct);
                return ResolvedSelection.Fail(why, page.Total);
            }
            read = page.Rows;
            keys = page.Rows.Select(r => Key(r, map.Spec.KeyColumn)).Where(k => k is not null).Select(k => k!).ToList();
        }
        else
        {
            if (sel.Ids.Count == 0) return ResolvedSelection.Fail("Select at least one row first.");
            if (sel.Ids.Count > action.BulkLimit)
                return ResolvedSelection.Fail($"{Rows(sel.Ids.Count)} are selected -- \"{action.Label}\" takes at most {Fmt.Int(action.BulkLimit)} at once. Narrow the selection.", sel.Ids.Count);
            keys = sel.Ids.ToList();
        }

        // each row -> what it stands for
        var matches = new List<(string Key, IReadOnlyList<FindingMatch> Matches)>();
        switch (map.Kind)
        {
            case RowMapKind.FromKey:
                foreach (var k in keys) matches.Add((k, map.FromKey!(k) is { IsEmpty: false } m ? new[] { m } : Array.Empty<FindingMatch>()));
                break;
            case RowMapKind.FromRow:
                if (read is null)
                {
                    var page = (await _views.ExportAsync(new GridQuery(map.Spec!, map.Parameters!(cur, sel), cur.Version + "|act",
                        new GridRequest { Selected = keys, Size = 50 }), ct)).Data;
                    read = page.Rows;
                }
                var byKey = read.Where(r => Key(r, map.Spec!.KeyColumn) is not null).GroupBy(r => Key(r, map.Spec!.KeyColumn)!, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
                foreach (var k in keys)
                    matches.Add((k, byKey.TryGetValue(k, out var row) && map.FromRow!(row) is { IsEmpty: false } m ? new[] { m } : Array.Empty<FindingMatch>()));
                break;
            case RowMapKind.Service:
                foreach (var k in keys)
                {
                    var svc = CollectionViewSql.ServiceKey(k);
                    var assets = (await _views.ExportAsync(new GridQuery(CollectionViewSql.ServiceAssets,
                        new Dictionary<string, object?> { ["CollectionId"] = cur.CollectionId, ["Service"] = svc }, cur.Version + "|act", new GridRequest { Size = 50 }), ct)).Data;
                    matches.Add((k, assets.Rows.Select(r => Key(r, "AssetKey")).Where(a => a is not null).Distinct(StringComparer.OrdinalIgnoreCase).Select(a => new FindingMatch(AssetKey: a)).ToList()));
                }
                break;
            case RowMapKind.CiGroup:
                foreach (var k in keys) matches.Add((k, await CiGroupMatchesAsync(k, ct)));
                break;
        }

        // ... and the findings, read once per asset (or once per issue across the assets), under the user's visibility
        var cache = new Dictionary<string, IReadOnlyList<IReadOnlyDictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        var found = new Dictionary<string, IReadOnlyDictionary<string, object?>>(StringComparer.Ordinal);
        var missing = new List<FindingActionResult>();
        foreach (var (key, list) in matches)
        {
            var hits = 0;
            foreach (var m in list)
            {
                var ck = m.AssetKey is not null ? "a:" + m.AssetKey : m.Issue is not null ? "i:" + m.Issue : "q:" + m.AssetName;
                if (!cache.TryGetValue(ck, out var rows))
                {
                    rows = await FindingRowsAsync(cur, m.AssetKey, m.AssetKey is null ? m.Issue : null, m.AssetKey is null && m.Issue is null ? m.AssetName : null, access, ct);
                    cache[ck] = rows;
                }
                foreach (var r in rows.Where(m.Matches))
                {
                    hits++;
                    if (Key(r, "FindingId") is { } id) found.TryAdd(id, r);
                }
                if (found.Count > max) break;
            }
            if (hits == 0) missing.Add(new FindingActionResult(key, null, null, false, $"this {map.RowNoun} row stands for no finding in this collection (or none you may see)"));
            if (found.Count > max) break;
        }
        if (found.Count > max)
        {
            var why = $"{Rows(keys.Count)} stand for more than {Fmt.Int(max)} findings -- \"{action.Label}\" takes at most {Fmt.Int(max)} at once. Narrow the selection.";
            if (sel.All) await GuardAsync(action, true, found.Count, max, why, ct);
            return ResolvedSelection.Fail(why, found.Count) with { Rows = keys.Count, RowNoun = map.RowNoun };
        }
        var findingRows = await RowsOfAsync(found.Values.ToList(), cur.CollectionId, ct);
        var targets = new List<GovernanceTarget>();
        foreach (var r in findingRows) targets.Add(await _threads.TargetAsync(r, ct));
        return new ResolvedSelection(targets, targets.Count, missing, targets.Count == 0 && missing.Count == 0 ? "No finding matches." : null)
        { Rows = keys.Count, RowNoun = map.RowNoun };
    }

    /// <summary>
    /// A Findings summary row (one finding x tier x severity x CMDB group of the CI data) as the findings it stands for:
    /// the CI data's "Findings per CI" rows of exactly that finding, tier, severity and CMDB group, each as that finding on
    /// its CI (<see cref="FindingRowMaps.CiFindingMatch"/>). No CI data = none (the row is listed as standing for no finding).
    /// </summary>
    private async Task<IReadOnlyList<FindingMatch>> CiGroupMatchesAsync(string key, CancellationToken ct)
    {
        if (_cis is null || FindingRowMaps.CiSummaryKey(key) is not { } g) return Array.Empty<FindingMatch>();
        var req = new GridRequest { Filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["FindingKey"] = g.FindingKey }, Size = 50 };
        var page = (await _cis.GridAsync(CiSql.FindingSpec, req, true, ct)).Data;
        bool Same(IReadOnlyDictionary<string, object?> r, string col, string want) => string.Equals((Key(r, col) ?? "").Trim(), want, StringComparison.OrdinalIgnoreCase);
        return page.Rows
            .Where(r => Same(r, "FindingKey", g.FindingKey) && Same(r, "Tier", g.Tier) && Same(r, "Severity", g.Severity) && Same(r, "CmdbId", g.CmdbId))
            .Select(r => Key(r, "RowKey") is { } rk ? FindingRowMaps.CiFindingMatch(rk) : null)
            .Where(m => m is not null).Select(m => m!).ToList();
    }

    private static string? Key(IReadOnlyDictionary<string, object?> r, string column) =>
        r.TryGetValue(column, out var v) && v is not null && Convert.ToString(v, CultureInfo.InvariantCulture) is { Length: > 0 } s ? s : null;

    /// The collection's finding rows of one asset (exact), of one issue (exact -- #330: never the free-text search, which
    /// scanned every searchable column of the whole collection and ran into the view time limit), or whose text matches
    /// an asset name (the caller keeps only the exact matches) -- limited to the user's departments as every grid read is.
    private async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> FindingRowsAsync(ViewCollection cur, string? assetKey, string? issue, string? search, DepartmentAccess access, CancellationToken ct)
    {
        var spec = issue is not null ? CollectionViewSql.RowsOfIssue : CollectionViewSql.Rows;
        var p = issue is not null
            ? new Dictionary<string, object?> { ["CollectionId"] = cur.CollectionId, ["Issue"] = issue.Trim() is { Length: > 400 } lng ? lng[..400] : issue.Trim() }
            : new Dictionary<string, object?> { ["CollectionId"] = cur.CollectionId, ["AssetKey"] = assetKey is null ? null : ProDataFilters.AssetKey(assetKey) };
        var scope = cur.Version;
        if (access.Rows is { } vis)
        {
            if (!DepartmentScope.CanRestrict(spec)) throw new ArgumentException("this view cannot be limited to your departments");
            spec = DepartmentScope.Restrict(spec, vis);
            foreach (var kv in vis.Parameters) p[kv.Key] = kv.Value;
            scope += "|" + vis.Key;
        }
        var req = new GridRequest { Search = search is null ? null : search.Length > 200 ? search[..200] : search, Size = 50 };
        return (await _views.ExportAsync(new GridQuery(spec, p, scope, req), ct)).Data.Rows;
    }

    private async Task<ViewCollection?> CollectionAsync(string? id, CancellationToken ct)
    {
        var cols = (await _views.CollectionsAsync(ct)).Data;
        return id is null ? cols.FirstOrDefault() : cols.FirstOrDefault(c => c.CollectionId == id);
    }

    /// The grid behind a collection / department view, with the user's department restriction (as the page applied it).
    private async Task<(GridSpec Spec, Dictionary<string, object?> Params, string Scope)?> GridAsync(FindingSelection sel, DepartmentAccess access, CancellationToken ct)
    {
        var cur = await CollectionAsync(sel.CollectionId, ct) ?? throw new ArgumentException("that collection is not in the Pro database");
        GridSpec spec;
        Dictionary<string, object?> p;
        string scope;
        if (sel.Source == SelectionSources.Department)
        {
            var unassigned = sel.Get("unassigned") == "1";
            var dept = sel.Get("id");
            if (!unassigned && (dept is null || !int.TryParse(dept, NumberStyles.None, CultureInfo.InvariantCulture, out var d) || d <= 0)) throw new ArgumentException("no department");
            // the Unassigned queue spans every department: never read for an account limited to departments
            if (unassigned && !access.Unrestricted) throw new ArgumentException("the Unassigned queue is not shown to an account limited to departments");
            spec = DepartmentSql.Findings;
            p = new Dictionary<string, object?> { ["CollectionId"] = cur.CollectionId, ["DepartmentId"] = unassigned ? null : dept, ["Unassigned"] = unassigned ? 1 : 0 };
            scope = cur.Version + (unassigned ? "|unassigned" : "|dept" + dept);
        }
        else
        {
            var key = sel.Get("key");
            spec = CollectionViewSql.Rows;
            p = new Dictionary<string, object?> { ["CollectionId"] = cur.CollectionId, ["AssetKey"] = key is null ? null : ProDataFilters.AssetKey(key) };
            scope = cur.Version;
        }
        if (access.Rows is { } vis)
        {
            if (!DepartmentScope.CanRestrict(spec)) throw new ArgumentException("this view cannot be limited to your departments");
            spec = DepartmentScope.Restrict(spec, vis);
            foreach (var kv in vis.Parameters) p[kv.Key] = kv.Value;
            scope += "|" + vis.Key;
        }
        return (spec, p, scope);
    }

    private async Task<IReadOnlyList<FindingRow>> SelectedAsync(FindingSelection sel, DepartmentAccess access, CancellationToken ct)
    {
        if (sel.Source == SelectionSources.Findings)
        {
            var list = new List<FindingRow>();
            foreach (var id in sel.Ids)
                if ((await _q.FindingAsync(sel.CollectionId, id, ct)).Data is { } d) list.Add(d.Finding);
            return list;
        }
        var g = (await GridAsync(sel, access, ct))!.Value;
        var page = (await _views.ExportAsync(new GridQuery(g.Spec, g.Params, g.Scope, new GridRequest { Selected = sel.Ids.ToList(), Size = 50 }), ct)).Data;
        return await RowsOfAsync(page.Rows, sel.CollectionId, ct);
    }

    private async Task<(IReadOnlyList<FindingRow>, long)> AllAsync(ClaimsPrincipal user, FindingSelection sel, DepartmentAccess access, int max, CancellationToken ct)
    {
        if (sel.Source == SelectionSources.Findings)
        {
            var f = ProDataFilters.Normalize(new FindingFilter
            {
                CollectionId = sel.CollectionId, Tier = sel.Get("tier"), Severity = sel.Get("sev"), Domain = sel.Get("dom"), Report = sel.Get("rep"),
                AssetKind = sel.Get("kind"), Text = sel.Get("q"), Visibility = _access.Visibility(user),
            });
            var rows = (await _q.ExportAsync(f, Math.Max(1, max) + 1, ct)).Data;
            return (rows, rows.Count);
        }
        var g = (await GridAsync(sel, access, ct))!.Value;
        var page = (await _views.ExportAsync(new GridQuery(g.Spec, g.Params, g.Scope, new GridRequest { Search = sel.Get("q"), Filters = sel.GridFilters.ToDictionary(kv => kv.Key, kv => kv.Value), Size = 50 }), ct)).Data;
        if (page.Total > max) return (Array.Empty<FindingRow>(), page.Total);
        return (await RowsOfAsync(page.Rows, sel.CollectionId, ct), page.Total);
    }

    /// A grid row as a finding row. The department grid carries no report: the finding's own row fills it in when the
    /// browser's reader has it.
    private async Task<IReadOnlyList<FindingRow>> RowsOfAsync(IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, string? collectionId, CancellationToken ct)
    {
        var cur = await CollectionAsync(collectionId, ct);
        string S(IReadOnlyDictionary<string, object?> r, string k) => r.TryGetValue(k, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";
        double D(IReadOnlyDictionary<string, object?> r, string k) => r.TryGetValue(k, out var v) && v is not null && double.TryParse(Convert.ToString(v, CultureInfo.InvariantCulture), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0;
        var list = new List<FindingRow>();
        foreach (var r in rows)
        {
            var id = S(r, "FindingId");
            if (id.Length == 0) continue;
            if (!r.ContainsKey("ReportName"))
            {
                try { if ((await _q.FindingAsync(cur?.CollectionId, id, ct)).Data is { } full) { list.Add(full.Finding); continue; } }
                catch (ArgumentException) { }
            }
            list.Add(new FindingRow(id, cur?.CollectionId ?? collectionId ?? "", cur?.CollectionTime, S(r, "AssetKey"), S(r, "AssetName"), S(r, "AssetKind"), S(r, "ReportName"),
                S(r, "SecurityDomain"), S(r, "ConfigurationId"), S(r, "Cve"), S(r, "Title"), S(r, "Severity"), S(r, "Tier") is { Length: > 0 } t ? t : ProDataFilters.Unclassified, D(r, "RiskScore")));
        }
        return list;
    }
}
