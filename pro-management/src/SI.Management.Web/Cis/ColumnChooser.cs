using System.Security.Claims;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Columns;

namespace SI.Management.Web.Cis;

/// One column a person can choose: its key, label, the group it is offered under and its hover text.
public sealed record ColumnChoice(string Key, string Label, string Group, string? Description = null);

/// <summary>
/// THE column chooser of a grid (Pages/Shared/_ColumnChooser.cshtml): the columns shown now (ticked, in order), the rest
/// per group to add, "Save for me" / (an Admin) "Save as the tenant default" and the two resets. The layouts are stored in
/// cfg.ColumnLayout under the grid's own view key (<see cref="IColumnLayoutStore"/>); the page posts to its own Columns /
/// Reset handlers.
/// It also carries what each person fine-tunes on the view itself: the named layouts to switch between (the selector), the
/// remembered sort and filters (with "Clear"), and the column widths -- and what the header's move / resize controls need.
/// </summary>
public sealed class ColumnChooser
{
    /// The view key the layout is stored under (cfg.ColumnLayout.[View]); the chooser posts it to the shared /Columns page.
    public string View { get; init; } = "";
    public required IReadOnlyList<ColumnChoice> Choices { get; init; }
    public required IReadOnlyList<string> Layout { get; init; }
    public required string Source { get; init; }
    public bool StoreReady { get; init; }
    /// Some lists of extra columns are not written yet by the data sync: the chooser offers what it has and says the rest
    /// appear after the next data sync (<see cref="PendingText"/>).
    public bool ExtrasPending { get; init; }
    public const string PendingText = "Some extra columns are not listed yet: they appear after the next data sync. Columns you already chose are kept.";
    /// The page with its grid state (where a save returns).
    public required string Return { get; init; }
    public bool IsAdmin { get; init; }

    /// The Pro database can keep the sort / filters, the widths and named layouts (cfg.ViewState, cfg.ViewLayout).
    public bool MoreReady { get; init; }
    /// The person's remembered sort / filters / search (JSON, <see cref="ViewState"/>); null = none.
    public string? State { get; init; }
    /// The page table keeps its sort and filters in the browser (the script restores them); else they are in the address.
    public bool ClientState { get; init; }
    /// A page table whose page also keeps its own filters in the address (the Findings browser, the task lists, the
    /// Summary): the filters are remembered from the address, each table's own sort in the browser.
    public bool AddressState { get; init; }
    /// What the page's script remembers the state from: "address" (a grid), "client" (a page table), or both.
    public string StateMode => !ClientState ? "address" : AddressState ? "address client" : "client";
    /// The address parameters that are this view's state (space-separated; the script and the server use the same list).
    public string StateKeys => ViewState.KeyListOf(View);
    /// The person's column widths (JSON {"column key": pixels}); null = none.
    public string? Widths { get; init; }
    /// The named layouts the person can switch between: their own, then the published ones.
    public IReadOnlyList<NamedLayout> Named { get; init; } = Array.Empty<NamedLayout>();
    public int? ActiveId { get; init; }
    public bool ActiveChanged { get; init; }

    /// The named layout in use (null = none).
    public NamedLayout? Active => ActiveId is { } id ? Named.FirstOrDefault(n => n.Id == id) : null;
    /// Something is remembered that "Clear" would take away (the rows per page alone is not worth a line on the view).
    public bool HasState => ViewState.Parse(State, View).Any(kv => !kv.Key.Equals("size", StringComparison.OrdinalIgnoreCase));

    /// An element id of this chooser (a page may hold several): the view key's letters, digits, '-' and '_'.
    public string ElementId => "view-" + new string(View.Select(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' ? ch : '-').ToArray());

    public ColumnChoice? Find(string key) => Choices.FirstOrDefault(c => c.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

    public static string SourceText(string s) => s == ColumnLayout.FromUser ? "your own columns" : s == ColumnLayout.FromTenant ? "the tenant default columns" : "the standard columns";

    /// What the columns shown are, in words: the layout in use by its name, else <see cref="SourceText"/>.
    public static string SourceWords(string source, NamedLayout? active, bool changed) =>
        active is null ? SourceText(source)
        : (active.Shared ? "the layout \"" : "your layout \"") + active.Name + "\"" + (changed ? ", changed since" : "");

    public string Words => SourceWords(Source, Active, ActiveChanged);

    // ---- the picker's "Add" lists (owner 2026-10-19): friendly words first, the technical name small under them, grouped
    // by what a person looks for -- the finding, its risk, the asset (CI), ServiceNow / CMDB -- then each source ----------

    public const string AddFinding = "Finding";
    public const string AddRisk = "Risk";
    public const string AddAsset = "Asset / CI";
    public const string AddCmdb = "ServiceNow / CMDB";

    /// The order the Add groups come in: this view's own columns, then the four above, then any other (a source's).
    public static readonly string[] AddOrder = [DataColumnKeys.GroupView, AddFinding, AddRisk, AddAsset, AddCmdb];

    /// The group a column is offered under in the Add lists.
    public static string AddGroup(ColumnChoice c)
    {
        var k = c.Key;
        var name = DataColumnKeys.TechnicalName(k).ToLowerInvariant();
        if (k.StartsWith(DataColumnKeys.SourceGroupPrefix, StringComparison.Ordinal) || DataColumnKeys.SourceOf(k) is not null) return c.Group;
        if (DataColumnKeys.IsFinding(k)) return IsRisk(name) ? AddRisk : AddFinding;
        if (DataColumnKeys.IsCi(k)) return name.Contains("cmdb", StringComparison.Ordinal) || name.Contains("servicenow", StringComparison.Ordinal) || name.StartsWith("si_service_", StringComparison.Ordinal) ? AddCmdb : AddAsset;
        return c.Group == DataColumnKeys.GroupView ? DataColumnKeys.GroupView : c.Group;
    }

    private static bool IsRisk(string name) =>
        name.Contains("risk", StringComparison.Ordinal) || name.Contains("score", StringComparison.Ordinal) || name.Contains("probability", StringComparison.Ordinal)
        || name.Contains("impact", StringComparison.Ordinal) || name.Contains("criticality", StringComparison.Ordinal) || name.Contains("exploit", StringComparison.Ordinal)
        || name.Contains("epss", StringComparison.Ordinal) || name.Contains("cvss", StringComparison.Ordinal);

    /// The columns not shown now, per Add group, in <see cref="AddOrder"/> (then the other groups as they come).
    public IReadOnlyList<IGrouping<string, ColumnChoice>> AddGroups(ISet<string> shown) =>
        Choices.Where(c => !shown.Contains(c.Key)).GroupBy(AddGroup)
            .OrderBy(g => Array.IndexOf(AddOrder, g.Key) is var i && i >= 0 ? i : AddOrder.Length).ToList();

    /// The technical name shown small under a column's words (nothing when it says the same as the words).
    public static string? Technical(ColumnChoice c)
    {
        var t = DataColumnKeys.TechnicalName(c.Key);
        return string.Equals(t, c.Label, StringComparison.OrdinalIgnoreCase) ? null : t;
    }
}

/// <summary>Saving and resetting a layout -- the same rules on every grid: a person saves their own; only an Admin the tenant default.</summary>
public static class ColumnChooserActions
{
    public sealed record Outcome(bool Forbidden, bool Ok, string Message);

    public const string NotYet = "Not saved: this part of the Pro database is not there yet (the next settings update adds it).";

    public static async Task<Outcome> SaveAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, string? scope, IEnumerable<string?> columns, Func<string, string?> known, CancellationToken ct)
    {
        var tenant = scope == SqlColumnLayoutStore.ScopeTenant;
        if (tenant && !user.IsAdmin()) return new(true, false, "");
        var keys = ColumnLayout.Clean(columns, known);
        if (keys.Count == 0) return new(false, false, "Not saved: tick at least one column.");
        var saved = await store.SaveAsync(tenant ? SqlColumnLayoutStore.ScopeTenant : SqlColumnLayoutStore.ScopeUser, user.ChangeName(), view, ColumnLayout.ToJson(keys), user.ChangeName(), ct);
        if (!saved) return new(false, false, "Not saved: the column layouts are not in the Pro database yet (the next settings update adds them).");
        return new(false, true, tenant ? "Saved as the tenant default: everyone without a layout of their own sees these columns." : "Saved: these are your columns on this page.");
    }

    public static async Task<Outcome> ResetAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, string? scope, CancellationToken ct)
    {
        var tenant = scope == SqlColumnLayoutStore.ScopeTenant;
        if (tenant && !user.IsAdmin()) return new(true, false, "");
        var done = await store.ResetAsync(tenant ? SqlColumnLayoutStore.ScopeTenant : SqlColumnLayoutStore.ScopeUser, user.ChangeName(), view, ct);
        if (!done) return new(false, false, "Nothing to reset: the column layouts are not in the Pro database yet.");
        // a person back on the tenant default has its widths and no layout in use (their sort and filters have their own Clear)
        if (!tenant) await store.ClearSettingsAsync(user.ChangeName(), view, ct);
        return new(false, true, tenant ? "The tenant default is the shipped default again." : "Reset: you see the tenant default columns again.");
    }

    /// The person's last sort / filters / search of a view, as the browser reports it after a change made on the page.
    public static async Task<Outcome> StateAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, string? queryText, CancellationToken ct) =>
        await store.SaveStateAsync(user.ChangeName(), view, ViewState.OfQueryText(queryText, view), ct) ? new(false, true, "") : new(false, false, NotYet);

    /// "Clear": the view's standard sort and filters again.
    public static async Task<Outcome> ClearStateAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, CancellationToken ct) =>
        await store.SaveStateAsync(user.ChangeName(), view, null, ct)
            ? new(false, true, "Cleared: this view shows its standard sort and filters again.")
            : new(false, false, "Nothing to clear: this part of the Pro database is not there yet.");

    /// The person's column widths of a view (every width they set; none = all back to automatic).
    public static async Task<Outcome> WidthsAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, string? widthsJson, CancellationToken ct) =>
        await store.SaveWidthsAsync(user.ChangeName(), view, ViewState.WidthsJson(widthsJson), ct) ? new(false, true, "") : new(false, false, NotYet);

    private static Outcome Named(string outcome, string ok) => outcome switch
    {
        LayoutOutcome.Saved => new(false, true, ok),
        LayoutOutcome.Forbidden => new(true, false, ""),
        LayoutOutcome.Gone => new(false, false, "That layout no longer exists. Your columns are unchanged."),
        LayoutOutcome.Taken => new(false, false, "Not saved: another layout already has that name."),
        _ => new(false, false, "Not saved: named layouts are not in the Pro database yet (the next settings update adds them)."),
    };

    /// <summary>
    /// Saves the set-up shown -- the ticked columns in their order, the sort / filters the page shows (<paramref name="returnUrl"/>;
    /// else the remembered ones) and the person's widths -- under a name (a new layout; the same name replaces), or with
    /// <paramref name="id"/> into that layout. <paramref name="publish"/>: for everyone (an Admin only).
    /// </summary>
    public static async Task<Outcome> SaveNamedAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, int? id, string? name, bool publish,
        IEnumerable<string?> columns, string? returnUrl, Func<string, string?> known, CancellationToken ct)
    {
        var admin = user.IsAdmin();
        if (publish && !admin) return new(true, false, "");
        var keys = ColumnLayout.Clean(columns, known);
        if (keys.Count == 0) return new(false, false, "Not saved: tick at least one column.");
        var n = id is null ? ViewState.Name(name) : "";
        if (n is null) return new(false, false, "Not saved: give the layout a name (at most 80 characters).");
        var state = ViewState.OfUrl(returnUrl, view);
        var (outcome, _) = await store.SaveNamedAsync(
            new NamedLayoutWrite(id, user.ChangeName(), view, n, publish, admin, ColumnLayout.ToJson(keys), state, state is null, user.ChangeName()), ct);
        return Named(outcome, id is not null ? "Saved: the layout has the columns, sort, filters and widths shown now."
            : publish ? "Saved the layout \"" + n + "\" for everyone." : "Saved the layout \"" + n + "\". Switch between your layouts with the Layout box.");
    }

    public static async Task<Outcome> ApplyNamedAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, int id, CancellationToken ct) =>
        Named(await store.ApplyNamedAsync(id, user.ChangeName(), view, ct), "This view now shows that layout.");

    public static async Task<Outcome> RenameNamedAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, int id, string? name, CancellationToken ct)
    {
        if (ViewState.Name(name) is not { } n) return new(false, false, "Not renamed: give the layout a name (at most 80 characters).");
        return Named(await store.RenameNamedAsync(id, user.ChangeName(), view, n, user.IsAdmin(), user.ChangeName(), ct), "Renamed to \"" + n + "\".");
    }

    public static async Task<Outcome> DeleteNamedAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, int id, CancellationToken ct) =>
        Named(await store.DeleteNamedAsync(id, user.ChangeName(), view, user.IsAdmin(), ct), "Deleted. The columns shown stay as they are.");

    /// Publishes one of the Admin's own layouts for everyone.
    public static async Task<Outcome> PublishNamedAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, int id, CancellationToken ct)
    {
        if (!user.IsAdmin()) return new(true, false, "");
        return Named(await store.PublishNamedAsync(id, user.ChangeName(), view, user.ChangeName(), ct), "Published: everyone can choose this layout; only an Admin can change it.");
    }

    /// The page a pinned view opens: the local path the person pinned it from, without a sort, filter or page (those are
    /// the layout's), its own parameters (one CI, one service) kept; null = not a local page address.
    public static string? PinPath(string? returnUrl, string view)
    {
        if (returnUrl is not { Length: > 1 } r || r[0] != '/' || r[1] is '/' or '\\') return null;
        var path = ViewState.WithoutMarker(ViewState.WithoutState(r, view));
        return path.Length <= SqlColumnLayoutStore.MaxPinPath ? path : null;
    }

    /// Pins a named layout to the menu or takes it off (owner 2026-10-19: "pinned views to the menu"): <paramref name="forAll"/>
    /// = everyone's menu, an Admin and a published layout only; else the person's own "My views".
    public static async Task<Outcome> PinNamedAsync(IColumnLayoutStore store, ClaimsPrincipal user, string view, int id, bool pin, bool forAll, string? returnUrl, CancellationToken ct)
    {
        if (forAll && !user.IsAdmin()) return new(true, false, "");
        var path = PinPath(returnUrl, view);
        if (path is null) return new(false, false, "Not pinned: open the view first, then pin the layout from it.");
        return Named(await store.PinNamedAsync(id, user.ChangeName(), view, pin, forAll, user.IsAdmin(), path, user.ChangeName(), ct),
            pin ? (forAll ? "Pinned for everyone: the layout is in everyone's Views menu." : "Pinned: the layout is in your Views menu (My views).")
                : (forAll ? "Taken off everyone's Views menu." : "Taken off your Views menu."));
    }
}
