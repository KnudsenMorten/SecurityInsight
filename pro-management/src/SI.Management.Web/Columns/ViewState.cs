using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Columns;

/// <summary>
/// A person's last sort / filters / search of one data view (owner 2026-10-11: "it must be saved per user, so when they
/// login again they see last config"), and their column widths. PURE apart from <see cref="Apply"/>.
/// <para>THE STATE is the view's own address parameters -- sort, dir, q, size, f.&lt;column&gt; and the named filters of the
/// CI grids (<see cref="Keys"/>) -- kept as a JSON object {"parameter": ["value", ...]} with the parameters in order, so
/// the same state is always the same text. A page table sorted and filtered in the browser keeps its state under t.*
/// parameters, which only the browser reads. The page number and the selected rows are never part of it.</para>
/// <para>THE RULE: an address that names any of those parameters wins and is shown exactly as today (links, bookmarks,
/// drill-downs, exports); only an address that names none gets the person's stored state -- put into the request's query
/// before the page reads it, so the page, its links and its exports all see one state. Nothing is written here: the
/// browser reports a change the person made ON the page to the shared /Columns page.</para>
/// </summary>
public static class ViewState
{
    /// The address parameters that are a view's state (lower case).
    public static readonly IReadOnlySet<string> Keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "sort", "dir", "q", "size",
        // the named filters of All CIs, the CI data grids and the records
        "class", "type", "subtype", "tier", "tiersetby", "lifecycle", "provider", "severity", "state",
    };

    /// <summary>
    /// A view whose filters are its PAGE's own address parameters, bound by the page before its table exists (the Findings
    /// browser, the task lists, the Risk Analysis Summary): exactly the parameters that are its state -- its own names,
    /// listed one by one, never a pattern -- and the value each has when the person chose nothing (a filter form posts every
    /// field: the standard is not worth remembering). A parameter that is NOT listed (the collection, the page number, the
    /// one row opened, the pivot's direction) is the page's own and is never stored.
    /// </summary>
    public sealed record PageState(IReadOnlySet<string> Keys, IReadOnlyDictionary<string, string> Standard);

    private static PageState Page(string[] keys, params (string Key, string Value)[] standard) =>
        new(new HashSet<string>(keys, StringComparer.OrdinalIgnoreCase), standard.ToDictionary(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase));

    private static readonly PageState TaskLists = Page(["show", "dept", "q", "sort", "dir", "size"], ("show", "open"), ("sort", "due"), ("size", "50"));

    /// The page views, by their view key (the key their layout is stored under).
    public static readonly IReadOnlyDictionary<string, PageState> Pages = new Dictionary<string, PageState>(StringComparer.OrdinalIgnoreCase)
    {
        ["findings"] = Page(["tier", "sev", "dom", "rep", "kind", "q", "sort", "size"], ("sort", "importance"), ("size", "50")),
        ["tasks-mine"] = TaskLists, ["tasks-delegated"] = TaskLists, ["tasks-all"] = TaskLists,
        ["summary"] = Page(["tier", "rating", "severity", "domain", "category", "subcategory", "cmdb", "report", "q", "size"], ("size", "25")),
    };

    /// A column filter of the shared grid (f.&lt;column&gt;).
    public const string FilterPrefix = "f.";
    /// The state of a table that is sorted and filtered in the browser: t.sort, t.dir, t.q, t.f.&lt;column&gt; -- and, since a
    /// view may show several tables, the same per table: t.&lt;table id&gt;/sort, t.&lt;table id&gt;/f.&lt;column&gt; ...
    public const string ClientPrefix = "t.";
    /// Set on the request by a page whose tables are the page's own (sorted in the browser): nothing is put into its query.
    public const string PageTablesItem = "si.view.pagetables";
    /// Set on the request by a page whose filters are its own address parameters: the view key they are remembered under.
    public const string AddressViewItem = "si.view.addressview";
    /// Set on the request when the remembered state of <see cref="AddressViewItem"/> was put into its query.
    public const string AppliedItem = "si.view.applied";

    public const int MaxKeys = 80;
    public const int MaxValues = 60;
    public const int MaxValue = 400;
    /// The longest parameter name (a table's own filter: t.&lt;table id&gt;/f.&lt;column key&gt;).
    public const int MaxKeyLength = 160;
    public const int MinWidth = 40;
    public const int MaxWidth = 2000;

    public static bool IsClientKey(string key) => key.StartsWith(ClientPrefix, StringComparison.OrdinalIgnoreCase);

    /// The address parameters that are the state of this view: a page view's own (<see cref="Pages"/>), else <see cref="Keys"/>.
    public static IReadOnlySet<string> KeysOf(string? view) => view is not null && Pages.TryGetValue(view, out var page) ? page.Keys : Keys;

    /// Whether an address parameter is part of a view's state.
    public static bool IsKey(string? key, string? view = null) =>
        !string.IsNullOrEmpty(key) && key.Length <= MaxKeyLength
        && (KeysOf(view).Contains(key) || key.StartsWith(FilterPrefix, StringComparison.OrdinalIgnoreCase) || IsClientKey(key));

    /// The space-separated list the browser uses (the same rule on both sides).
    public static string KeyList => KeyListOf(null);

    /// <see cref="KeyList"/> of one view.
    public static string KeyListOf(string? view) => string.Join(" ", KeysOf(view).Select(k => k.ToLowerInvariant()).OrderBy(k => k, StringComparer.Ordinal));

    /// Whether an address names a sort, a filter or a search (then it wins over what is stored).
    public static bool Names(IEnumerable<string> queryKeys, string? view = null) => queryKeys.Any(k => IsKey(k, view) && !IsClientKey(k));

    /// A stored state: parameter -> values (empty for nothing, invalid JSON or anything that is not such an object).
    public static IReadOnlyList<KeyValuePair<string, IReadOnlyList<string>>> Parse(string? json, string? view = null)
    {
        var result = new List<KeyValuePair<string, IReadOnlyList<string>>>();
        if (string.IsNullOrWhiteSpace(json)) return result;
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Object) return result;
            foreach (var p in d.RootElement.EnumerateObject())
            {
                if (!IsKey(p.Name, view) || p.Value.ValueKind != JsonValueKind.Array) continue;
                var values = p.Value.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).Where(v => v.Length > 0).ToList();
                if (values.Count > 0) result.Add(new(p.Name, values));
            }
        }
        catch (JsonException) { result.Clear(); }
        return result;
    }

    /// <summary>
    /// The state named by some address parameters, as it is stored: only state parameters, no empty value, the parameters in
    /// order (ordinal), within the limits. Null = no state (the view's standard). A page view's standard value of a
    /// parameter (<see cref="PageState.Standard"/>) is no state either.
    /// </summary>
    public static string? ToJson(IEnumerable<KeyValuePair<string, StringValues>> query, string? view = null)
    {
        var standard = view is not null && Pages.TryGetValue(view, out var page) ? page.Standard : null;
        var state = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var kv in query)
        {
            if (!IsKey(kv.Key, view)) continue;
            foreach (var v in kv.Value)
            {
                if (string.IsNullOrWhiteSpace(v)) continue;
                if (standard is not null && standard.TryGetValue(kv.Key, out var usual) && string.Equals(v.Trim(), usual, StringComparison.OrdinalIgnoreCase)) continue;
                if (!state.TryGetValue(kv.Key, out var list))
                {
                    if (state.Count >= MaxKeys) break;
                    state[kv.Key] = list = new List<string>();
                }
                if (list.Count < MaxValues) list.Add(v.Length > MaxValue ? v[..MaxValue] : v);
            }
        }
        return state.Count == 0 ? null : JsonSerializer.Serialize(state);
    }

    /// The state an address (a local path with its query) names; null when it names none.
    public static string? OfUrl(string? url, string? view = null)
    {
        var at = url?.IndexOf('?') ?? -1;
        if (url is null || at < 0) return null;
        var query = QueryHelpers.ParseQuery(url[(at + 1)..]);
        return Names(query.Keys, view) ? ToJson(query, view) : null;
    }

    /// The state the browser reports: the page's query text ("?sort=Risk&amp;dir=desc" or "t.sort=Name"), as it is stored.
    public static string? OfQueryText(string? text, string? view = null) =>
        string.IsNullOrWhiteSpace(text) ? null : ToJson(QueryHelpers.ParseQuery(text.TrimStart('?')), view);

    /// A local address without its state parameters and page number (where "Clear" and choosing a layout return to: the
    /// stored state then decides what shows).
    public static string WithoutState(string url, string? view = null)
    {
        var at = url.IndexOf('?');
        if (at < 0) return url;
        var parts = new List<string>();
        foreach (var kv in QueryHelpers.ParseQuery(url[(at + 1)..]))
        {
            if (IsKey(kv.Key, view) || kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add(Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(v));
        }
        return url[..at] + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    // ---- opened from the menu ------------------------------------------------------------------------------------------

    /// <summary>
    /// THE mark of a view opened from the MENU (owner 2026-10-11): the menu's links to the data views carry nav=menu, and
    /// a person's remembered sort / filters come back ONLY then. A dashboard tile, a link from another page or a mail, and
    /// a typed address show the view's standard (or what the link names) -- a tile that says "128 critical" never opens a
    /// list filtered to something else. The mark is not state: it is never stored, and it is taken out of the request
    /// before the page reads its address, so no link, export or return address of the page carries it on. It stays in the
    /// browser's address, so loading the page again shows the remembered state again.
    /// </summary>
    public const string MenuMarker = "nav";
    public const string MenuValue = "menu";
    /// Set on the request once the mark was seen (and taken out of its query).
    public const string MenuItem = "si.view.frommenu";

    /// Whether this request opened the view from the menu. The first call takes the mark out of the request's query.
    public static bool FromMenu(HttpContext http)
    {
        if (http.Items.ContainsKey(MenuItem)) return true;
        var query = http.Request.Query;
        if (!query.TryGetValue(MenuMarker, out var mark)) return false;
        var rest = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in query) if (!kv.Key.Equals(MenuMarker, StringComparison.OrdinalIgnoreCase)) rest[kv.Key] = kv.Value;
        http.Request.Query = new QueryCollection(rest);
        if (!string.Equals(mark.ToString(), MenuValue, StringComparison.Ordinal)) return false;
        http.Items[MenuItem] = true;
        return true;
    }

    /// A local address without the menu's mark (a return address, an export link: the mark never travels on).
    public static string WithoutMarker(string url)
    {
        var at = url.IndexOf('?');
        if (at < 0) return url;
        var parts = url[(at + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => !(p.Equals(MenuMarker, StringComparison.OrdinalIgnoreCase) || p.StartsWith(MenuMarker + "=", StringComparison.OrdinalIgnoreCase))).ToList();
        return url[..at] + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    /// Whether a local address names a sort, a filter or a search of the view.
    public static bool NamesState(string url, string? view = null)
    {
        var at = url.IndexOf('?');
        return at >= 0 && Names(QueryHelpers.ParseQuery(url[(at + 1)..]).Keys, view);
    }

    /// A local address with the menu's mark: what is stored for the person decides what the view shows.
    public static string WithMarker(string url)
    {
        var plain = WithoutMarker(url);
        return plain + (plain.Contains('?') ? "&" : "?") + MenuMarker + "=" + MenuValue;
    }

    /// The address a MENU link opens a page with: a data view (<see cref="DataViews"/>) gets the mark, any other page is as it is.
    public static string MenuHref(string? href, string page) =>
        string.IsNullOrEmpty(href) ? href ?? "" : DataViews.IsDataView(page) ? WithMarker(href) : href;

    /// Whether a stored state would be put into this request at all: a plain page view (a GET without a handler) opened
    /// FROM THE MENU whose address names no sort, filter or search, and not a page whose tables are sorted in the browser.
    public static bool CanApply(HttpContext http, string? view = null)
    {
        var menu = FromMenu(http);
        var req = http.Request;
        return menu && HttpMethods.IsGet(req.Method) && !req.Query.ContainsKey("handler") && !http.Items.ContainsKey(PageTablesItem) && !Names(req.Query.Keys, view)
            && !NamesASet(req.Query.Keys);
    }

    /// <summary>
    /// #864 (owner 2026-10-21): the address parameters that name WHICH rows a page shows (a remediation's findings: fix=).
    /// Such an address is a link to exactly those rows: a person's remembered filters are never put on top of it, even
    /// with the menu's mark -- a remembered "Domain = ..." would silently narrow a fix's findings.
    /// </summary>
    public static readonly IReadOnlySet<string> SetKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "fix" };

    /// Whether an address names the set of rows it opens (<see cref="SetKeys"/>).
    public static bool NamesASet(IEnumerable<string> queryKeys) => queryKeys.Any(SetKeys.Contains);

    /// <summary>
    /// Puts a person's stored state into the request's query -- only on a plain page view (a GET without a handler) whose
    /// address names no sort, filter or search, and never on a page whose tables are sorted in the browser. True = the page
    /// now shows the stored state.
    /// </summary>
    public static bool Apply(HttpContext? http, string? stateJson, string? view = null)
    {
        if (http is null || string.IsNullOrEmpty(stateJson) || !CanApply(http, view)) return false;
        var req = http.Request;
        var stored = Parse(stateJson, view).Where(kv => !IsClientKey(kv.Key)).ToList();
        if (stored.Count == 0) return false;
        var merged = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in req.Query) merged[kv.Key] = kv.Value;
        foreach (var kv in stored) merged[kv.Key] = new StringValues(kv.Value.ToArray());
        req.Query = new QueryCollection(merged);
        return true;
    }

    // ---- the column widths ---------------------------------------------------------------------------------------------

    /// Stored widths: column key -> pixels (empty for nothing or anything that is not such an object).
    public static IReadOnlyDictionary<string, int> ParseWidths(string? json)
    {
        var result = new SortedDictionary<string, int>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json)) return result;
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Object) return result;
            foreach (var p in d.RootElement.EnumerateObject())
            {
                if (result.Count >= ColumnLayout.MaxColumns) break;
                if (!WellFormedColumn(p.Name) || p.Value.ValueKind != JsonValueKind.Number || !p.Value.TryGetInt32(out var px)) continue;
                result[p.Name] = Math.Clamp(px, MinWidth, MaxWidth);
            }
        }
        catch (JsonException) { result.Clear(); }
        return result;
    }

    /// The widths as they are stored (well-formed column keys, whole pixels within the limits, in order); null = none.
    public static string? WidthsJson(string? posted)
    {
        var w = ParseWidths(posted);
        return w.Count == 0 ? null : JsonSerializer.Serialize(w);
    }

    /// A key a layout may hold: a plain column key of a view, or a well-formed extra column key.
    public static bool WellFormedColumn(string key) => GridSql.IsKey(key) || DataColumnKeys.IsValid(key);

    /// A layout's name as it is kept: trimmed, one line, at most 80 characters; null = not a name.
    public static string? Name(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var n = string.Join(" ", name.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        n = new string(n.Where(ch => !char.IsControl(ch)).ToArray());
        return n.Length is 0 or > SI.Management.Web.Cis.SqlColumnLayoutStore.MaxName ? null : n;
    }

    /// A layout id from a form ("12"); null = none.
    public static int? Id(string? value) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var id) && id > 0 ? id : null;
}
