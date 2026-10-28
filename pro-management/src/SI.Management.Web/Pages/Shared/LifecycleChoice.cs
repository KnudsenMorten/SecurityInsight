using Microsoft.AspNetCore.Http;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages;

/// <summary>
/// #855 THE LIFECYCLE CHOICE OF A VIEW (owner 2026-10-21: "default filter is active, so it should be active only"): Active
/// (the default) | Not seen | Retired | All, as the shared segmented control (Pages/Shared/_LifecycleChoice.cshtml), each a link
/// to the same page with the lifecycle parameter set (paging reset) -- the CI list's own parameter and values
/// (lifecycle=not_seen, lifecycle=all). The page reads its filter with <see cref="Read"/> and passes it to its reader; the
/// ViewScope line says what is counted (<see cref="LifecycleFilter.Words"/>).
/// </summary>
public sealed record LifecycleChoice(LifecycleFilter Current, string Path, IReadOnlyList<KeyValuePair<string, string?>> Query)
{
    /// The query parameters a choice drops: the page it was on (the counts change).
    private static readonly HashSet<string> Dropped = new(StringComparer.OrdinalIgnoreCase) { LifecycleFilter.Parameter, "page", "p" };

    /// The lifecycle filter of a request (none = the default, active).
    public static LifecycleFilter Read(HttpRequest? request) =>
        request is null ? LifecycleFilter.Active : LifecycleFilter.Parse(request.Query[LifecycleFilter.Parameter].ToArray());

    /// The choice of a request (its path and its other parameters kept).
    public static LifecycleChoice For(HttpRequest request, LifecycleFilter? current = null) =>
        new(current ?? Read(request), request.PathBase.Add(request.Path).Value ?? "/",
            request.Query.Where(q => !Dropped.Contains(q.Key)).SelectMany(q => q.Value.Select(v => new KeyValuePair<string, string?>(q.Key, v))).ToList());

    /// The address of this page with the lifecycle parameter set to <paramref name="value"/> (null = the default: no parameter).
    public string Link(string? value)
    {
        var q = Query.ToList();
        if (value is { Length: > 0 }) q.Add(new(LifecycleFilter.Parameter, value));
        return q.Count == 0 ? Path : Path + Microsoft.AspNetCore.Http.QueryString.Create(q).ToUriComponent();
    }

    /// The four choices with their links and which is chosen (a multi-state filter chooses none of them).
    public IReadOnlyList<(string Value, string Label, string Href, bool Chosen)> Options =>
    [
        ("active", "Active", Link(null), Current.IsActiveOnly),
        ("not_seen", "Not seen", Link("not_seen"), Current.States is { Count: 1 } a && a[0] == "not_seen"),
        ("retired", "Retired", Link("retired"), Current.States is { Count: 1 } b && b[0] == "retired"),
        ("all", "All", Link(CiLifecycleDefinitions.ClearedFilter), Current.IsAll),
    ];
}
