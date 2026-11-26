using SI.Management.Core.ProData;
using SI.Management.Web.Collection;

namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// #1386 THE compact header of every collection view (owner 2026-11-25, screenshot of Remediations &gt; Tasks per asset: "i
/// feel the si views contain much noise that takes of space" -- the run date was shown three times and ~300 px came before
/// the grid; he chose "One line"):
/// <code>
///   Tasks per asset                                    ▸ About this page
///   4,946 tasks · data from [ 25-11-2026 18:56 · 18,029 rows · newest ▾ ]
///   [ Search every text column ][Apply][Clear][Filters][Columns] ...
/// </code>
/// The run date is shown ONCE, by the collection picker (Pages/Collection/_Header.cshtml). The page's explanation and the
/// "What you're looking at" statement with "What these words mean" sit inside the collapsed "About this page" -- every word
/// kept. What stays visible is what needs attention: an OLDER collection than the newest is marked, the partial / source /
/// error notices, the person's filters as chips, and the layout's run line whenever it says more than the date (a newer run
/// in progress, the newest run did not complete, part of the run from an earlier result, findings per CI as of).
/// The header tells the layout and the grid (per request, <see cref="Microsoft.AspNetCore.Http.HttpContext.Items"/> -- the
/// page body is rendered before its layout) what it already showed, so neither says it again.
/// </summary>
public static class ViewHead
{
    /// Set by the header when it shows the collection's date: the layout leaves out its plain "Data from the run of" line.
    public const string RunShownKey = "si:viewhead:run-shown";
    /// Set by the header to the grid whose row count it shows: that grid's own count heading is kept for screen readers only.
    public const string CountedGridKey = "si:viewhead:counted-grid";

    /// The words of the mark an older collection gets (the newest is one click away).
    public const string OlderMark = "older collection";
    public const string OpenNewest = "Open the newest";

    /// PURE. Whether the collection shown is not the newest of the picker's list (the list is newest first).
    public static bool IsOlder(ViewCollection? current, IReadOnlyList<ViewCollection> collections) =>
        current is not null && collections.Count > 0 && collections[0].CollectionId != current.CollectionId;

    /// PURE. Whether the layout's run line is left out: the header already showed the date, and the line would say nothing
    /// else (no newer run going, no run that did not complete, nothing from an earlier result, no findings-per-CI time).
    public static bool LayoutRunLineRedundant(PublishedRunState state, bool runShownByHeader) =>
        runShownByHeader && PublishedRunNoticeText.Tail(state).Length == 0 && state.CiFindingsTime is null;

    /// "4,946 tasks" / "1 task" -- the grid's row count in the words of its noun.
    public static string Count(long total, string noun) => Fmt.Int(total) + " " + (total == 1 ? GridToolbar.Singular(noun) : GridToolbar.Plural(noun));
}
