using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Cis;
using SI.Management.Web.Columns;

namespace SI.Management.Web.Pages;

/// <summary>
/// THE save / reset of every data view's columns (Pages/Shared/_ColumnChooser.cshtml posts here with the view key): a
/// person saves their own layout, an Admin also the tenant default -- the same rules on every view
/// (<see cref="ColumnChooserActions"/>). The keys are kept when they are well formed (a view's own column key, or an extra
/// column key, <see cref="DataColumnKeys"/>); the view drops what it does not know when it reads the layout, so a stale
/// key never breaks a page. Returns to the page it came from (a local path only).
/// <para>Also everything else a person fine-tunes on a view (owner 2026-10-11: "any user can finetune each view ... it must
/// be saved per user"): the last sort / filters / search (State, ClearState), the column widths (Widths), a move of a
/// column on the table header (Save, answered without a page load) and the named layouts (LayoutSave, LayoutApply,
/// LayoutRename, LayoutDelete, LayoutPublish). Every one is the caller's own, by their sign-in name -- only a published
/// layout and the tenant default need an Admin, checked here on the server. A request the page's script sends
/// (X-Requested-With: fetch) is answered with { ok, message } instead of a redirect.</para>
/// </summary>
public sealed class ColumnsModel(IColumnLayoutStore store) : PageModel
{
    [BindProperty] public string? View { get; set; }
    [BindProperty] public List<string> Columns { get; set; } = new();
    [BindProperty] public string? Scope { get; set; }
    [BindProperty] public string? Return { get; set; }
    /// The view's address parameters as the browser reports them after a change on the page ("?sort=Risk&amp;dir=desc").
    [BindProperty] public string? State { get; set; }
    /// The person's column widths: a JSON object {"column key": pixels}.
    [BindProperty] public string? Widths { get; set; }
    /// A named layout's name (a new one, or the new name of an existing one).
    [BindProperty] public string? Name { get; set; }
    /// The named layout a request is about.
    [BindProperty] public string? LayoutId { get; set; }
    /// "1" = save the new layout for everyone (an Admin only).
    [BindProperty] public string? Publish { get; set; }
    /// "1" = a pin of everyone's menu (an Admin, a published layout); else the person's own "My views".
    [BindProperty] public string? ForAll { get; set; }

    /// A key a layout may hold: a plain column key of a view, or a well-formed extra column key.
    public static string? WellFormed(string key) => GridSql.IsKey(key) || DataColumnKeys.IsValid(key) ? key : null;

    /// A view key: letters, digits, '-', '_', '@', '.', at most <see cref="SqlColumnLayoutStore.MaxView"/>.
    public static bool ValidView(string? v) =>
        v is { Length: > 0 and <= SqlColumnLayoutStore.MaxView } && v.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or '@' or '.');

    public IActionResult OnGet() => LocalRedirect("/");

    /// A pinned view of the menu (owner 2026-10-19): its layout becomes the person's set-up of that view -- like choosing it
    /// in the Layout box, the person's own display state, no audit row -- and the view opens as the menu opens it. Only a
    /// layout pinned to THIS person's menu opens (their own pin, or one for everyone); anything else goes home.
    [SI.Management.Web.Audit.NotAudited(OwnStateReason)]
    public async Task<IActionResult> OnGetOpenAsync(int id, CancellationToken ct)
    {
        var pinned = (await store.PinnedAsync(User.ChangeName(), ct)).FirstOrDefault(p => p.Id == id);
        if (pinned is null || !ValidView(pinned.View) || ColumnChooserActions.PinPath(pinned.Path, pinned.View) is not { } path) return LocalRedirect("/");
        var outcome = await store.ApplyNamedAsync(id, User.ChangeName(), pinned.View, ct);
        if (outcome != LayoutOutcome.Saved)
        {
            TempData["toast"] = "That pinned view's layout no longer exists; the view opens as you left it.";
            TempData["toastKind"] = "error";
        }
        return LocalRedirect(ViewState.WithMarker(path));
    }

    /// The page's script asked (it reads the answer); a form post is answered with a redirect and a toast.
    private bool Scripted => string.Equals(Request.Headers["X-Requested-With"].ToString(), "fetch", StringComparison.OrdinalIgnoreCase);

    /// <param name="o">How the change ended.</param>
    /// <param name="standard">Return to the view WITHOUT the sort / filters of the address, so what is stored decides what shows.</param>
    private IActionResult Back(ColumnChooserActions.Outcome o, bool standard = false)
    {
        if (o.Forbidden) return Forbid();
        if (Scripted) return new JsonResult(new { ok = o.Ok, message = o.Message });
        if (o.Message.Length > 0)
        {
            TempData["toast"] = o.Message;
            TempData["toastKind"] = o.Ok ? "ok" : "error";
        }
        var back = Return is { Length: > 1 } r && r[0] == '/' && r[1] != '/' && r[1] != '\\' && Url.IsLocalUrl(r) ? r : "/";
        // "Clear" and choosing / saving a layout return to the view as the MENU opens it: what is stored decides what shows
        return LocalRedirect(standard && o.Ok && back != "/" ? ViewState.WithMarker(ViewState.WithoutState(back, View)) : back);
    }

    /// A change that the store refuses for its size or shape is told, never an error page.
    private async Task<IActionResult> RunAsync(Func<Task<ColumnChooserActions.Outcome>> change, bool standard = false)
    {
        if (!ValidView(View)) return BadRequest("unknown view");
        try { return Back(await change(), standard); }
        catch (ArgumentException ex) { return Back(new ColumnChooserActions.Outcome(false, false, "Not saved: " + ex.Message + ".")); }
    }

    [SI.Management.Web.Audit.Audited("view.columns.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        if (!ValidView(View)) return BadRequest("unknown view");
        return Back(await ColumnChooserActions.SaveAsync(store, User, View!, Scope, Columns, WellFormed, ct));
    }

    [SI.Management.Web.Audit.Audited("view.columns.reset")]
    public async Task<IActionResult> OnPostResetAsync(CancellationToken ct)
    {
        if (!ValidView(View)) return BadRequest("unknown view");
        return Back(await ColumnChooserActions.ResetAsync(store, User, View!, Scope, ct));
    }

    /// Why a person's own sort, filters and column widths write no audit row (owner 2026-10-11): the audit trail records
    /// LAYOUTS -- the columns of a view (a person's own and the tenant default) and the named layouts -- not how a person
    /// last sorted, filtered or sized their own view. Choosing a named layout is the same kind of thing (owner 2026-10-11:
    /// "do not audit switching"): it changes nothing but what that person sees, so <see cref="OnPostLayoutApplyAsync"/>
    /// carries this reason too. Creating, changing, renaming, deleting and publishing a layout stay recorded.
    public const string OwnStateReason = "a person's own last sort, filters or column widths of a view: their own display state, not a layout";

    /// The person's last sort / filters / search of the view, after a change they made on the page.
    [SI.Management.Web.Audit.NotAudited(OwnStateReason)]
    public Task<IActionResult> OnPostStateAsync(CancellationToken ct) =>
        RunAsync(() => ColumnChooserActions.StateAsync(store, User, View!, State, ct));

    /// "Clear": the view's standard sort and filters again.
    [SI.Management.Web.Audit.NotAudited(OwnStateReason)]
    public Task<IActionResult> OnPostClearStateAsync(CancellationToken ct) =>
        RunAsync(() => ColumnChooserActions.ClearStateAsync(store, User, View!, ct), standard: true);

    /// The person's column widths of the view.
    [SI.Management.Web.Audit.NotAudited(OwnStateReason)]
    public Task<IActionResult> OnPostWidthsAsync(CancellationToken ct) =>
        RunAsync(() => ColumnChooserActions.WidthsAsync(store, User, View!, Widths, ct));

    /// Saves the set-up shown under a name (or into the layout named by LayoutId); Publish = for everyone (an Admin only).
    [SI.Management.Web.Audit.Audited("view.layout.save")]
    public Task<IActionResult> OnPostLayoutSaveAsync(CancellationToken ct) =>
        RunAsync(() => ColumnChooserActions.SaveNamedAsync(store, User, View!, ViewState.Id(LayoutId), Name, Publish == "1", Columns, Return, WellFormed, ct), standard: true);

    /// Shows a named layout: its columns, order, sort, filters and widths become the person's set-up. Writes no audit
    /// row -- choosing a layout is a person's own view, like sorting; the layout itself is unchanged.
    [SI.Management.Web.Audit.NotAudited(OwnStateReason)]
    public Task<IActionResult> OnPostLayoutApplyAsync(CancellationToken ct) =>
        ViewState.Id(LayoutId) is { } id
            ? RunAsync(() => ColumnChooserActions.ApplyNamedAsync(store, User, View!, id, ct), standard: true)
            : RunAsync(() => Task.FromResult(new ColumnChooserActions.Outcome(false, true, "")));

    [SI.Management.Web.Audit.Audited("view.layout.rename")]
    public Task<IActionResult> OnPostLayoutRenameAsync(CancellationToken ct) =>
        ViewState.Id(LayoutId) is { } id
            ? RunAsync(() => ColumnChooserActions.RenameNamedAsync(store, User, View!, id, Name, ct))
            : Task.FromResult<IActionResult>(BadRequest("unknown layout"));

    [SI.Management.Web.Audit.Audited("view.layout.delete")]
    public Task<IActionResult> OnPostLayoutDeleteAsync(CancellationToken ct) =>
        ViewState.Id(LayoutId) is { } id
            ? RunAsync(() => ColumnChooserActions.DeleteNamedAsync(store, User, View!, id, ct))
            : Task.FromResult<IActionResult>(BadRequest("unknown layout"));

    /// Publishes one of the Admin's own layouts for everyone (refused to anyone else, here on the server).
    /// Pins a named layout to the menu: the person's own "My views", or (ForAll, an Admin) everyone's.
    [SI.Management.Web.Audit.Audited("view.layout.pin")]
    public Task<IActionResult> OnPostLayoutPinAsync(CancellationToken ct) =>
        ViewState.Id(LayoutId) is { } id
            ? RunAsync(() => ColumnChooserActions.PinNamedAsync(store, User, View!, id, true, ForAll == "1", Return, ct))
            : Task.FromResult<IActionResult>(BadRequest("unknown layout"));

    [SI.Management.Web.Audit.Audited("view.layout.unpin")]
    public Task<IActionResult> OnPostLayoutUnpinAsync(CancellationToken ct) =>
        ViewState.Id(LayoutId) is { } id
            ? RunAsync(() => ColumnChooserActions.PinNamedAsync(store, User, View!, id, false, ForAll == "1", Return, ct))
            : Task.FromResult<IActionResult>(BadRequest("unknown layout"));

    [SI.Management.Web.Audit.Audited("view.layout.publish")]
    public Task<IActionResult> OnPostLayoutPublishAsync(CancellationToken ct) =>
        ViewState.Id(LayoutId) is { } id
            ? RunAsync(() => ColumnChooserActions.PublishNamedAsync(store, User, View!, id, ct))
            : Task.FromResult<IActionResult>(BadRequest("unknown layout"));
}
