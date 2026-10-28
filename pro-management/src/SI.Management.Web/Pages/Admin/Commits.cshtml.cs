using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.ChangeJournal;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Operations &gt; Commits (undo) (#404, framework CONFIG-1.2): the commit history from the change journal -- who, when,
/// approved by, from where (the screen, an import, a restore, an undo, a job, a template install), what changed record by
/// record (before -> after per field) and what the commit did (its audit events). A SuperAdmin sees and undoes every
/// commit; an Admin only their own (the page's folder is Admin; a Delegated or read-only role never reaches it).
/// UNDO = the inverse of the chosen records STAGED as pending changes (nothing is written here): Review &amp; commit shows
/// them before -> after and commits them through the normal path, journaled with Source undo and UndoOf -- so an undo is
/// itself undoable. Every record is ticked by default except one a later commit changed again ("changed since by
/// &lt;who&gt;") -- reverting that is a deliberate tick.
/// </summary>
public sealed class CommitsModel : PageModel
{
    private readonly IConfigJournalStore _journal;
    private readonly ConfigEntities _entities;
    private readonly ConfigApplier _applier;
    private readonly ChangeService _changes;
    private readonly ILogger<CommitsModel> _log;
    public CommitsModel(IConfigJournalStore journal, ConfigEntities entities, ConfigApplier applier, ChangeService changes, ILogger<CommitsModel> log)
    { _journal = journal; _entities = entities; _applier = applier; _changes = changes; _log = log; }

    /// #857: the viewer's rows per page (one of GridSql.PageChoices; anything else the default).
    [BindProperty(SupportsGet = true, Name = "size")] public int Size { get; set; } = SI.Management.Core.ProData.GridSql.DefaultPageSize;
    public int PageSize => SI.Management.Core.ProData.GridSql.PageSize(Size);
    public const int ReasonMin = 10;

    [BindProperty(SupportsGet = true)] public string? Id { get; set; }
    [BindProperty(SupportsGet = true)] public string? Entity { get; set; }
    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true, Name = "p")] public int PageNo { get; set; } = 1;
    [BindProperty] public List<long> Pick { get; set; } = new();
    [BindProperty] public string? Reason { get; set; }

    /// The kinds of configuration the list is filtered to (none = everything).
    public IReadOnlyList<string> ChosenEntities { get; private set; } = Array.Empty<string>();
    public bool HasTable { get; private set; }
    public string? Error { get; private set; }
    public bool AllCommits => User.IsSuperAdmin();
    public IReadOnlyList<ConfigCommit> Commits { get; private set; } = Array.Empty<ConfigCommit>();
    public long Total { get; private set; }
    public IReadOnlyList<ConfigJournalRow> Rows { get; private set; } = Array.Empty<ConfigJournalRow>();
    public IReadOnlyList<ConfigUndo.Item> Plan { get; private set; } = Array.Empty<ConfigUndo.Item>();
    public IReadOnlyList<ConfigCommitEvent> Events { get; private set; } = Array.Empty<ConfigCommitEvent>();
    public ConfigEntities Entities => _entities;
    public bool MayUndo { get; private set; }
    public string? CannotUndo { get; private set; }

    /// An Admin's view is their own commits.
    private string? Scope => User.IsSuperAdmin() ? null : User.ChangeName();

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            HasTable = await _journal.ExistsAsync(ct);
            if (!HasTable) return;
            if (!string.IsNullOrWhiteSpace(Id)) { await LoadCommitAsync(Id, ct); return; }
            var page = Math.Max(1, PageNo);
            // "What" takes several kinds (one parameter per value, or '|'-joined): only names the journal knows travel on
            ChosenEntities = MultiFilter.ValuesOf(Request.Query, "entity").Select(e => _entities.Find(e)?.Name).Where(n => n is not null).Select(n => n!).Distinct().ToList();
            Entity = ChosenEntities.Count == 0 ? null : string.Join(SI.Management.Core.ProData.ProDataFilters.ValueSeparator, ChosenEntities);
            (Commits, Total) = await _journal.CommitsAsync(Scope, Entity, Q, (page - 1) * PageSize, PageSize, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the change journal failed");
            Error = "The commit history could not be read: " + ex.Message;
        }
    }

    private async Task LoadCommitAsync(string id, CancellationToken ct)
    {
        Rows = await _journal.CommitAsync(id, ct);
        if (Rows.Count == 0) { Error = "That commit is not in the change journal."; return; }
        // an Admin sees only their own commits: another person's reads as not found
        if (Scope is { } me && !Rows.All(r => string.Equals(r.InitiatedBy, me, StringComparison.OrdinalIgnoreCase)))
        {
            Rows = Array.Empty<ConfigJournalRow>();
            Error = "That commit is not one of yours. An Admin sees and undoes only their own commits; a SuperAdmin sees every commit.";
            return;
        }
        Plan = ConfigUndo.Plan(Rows, await _journal.LaterAsync(id, ct), _entities);
        Events = await _journal.EventsAsync(id, ct);
        MayUndo = Plan.Any(p => p.Blocked is null);
        if (!MayUndo) CannotUndo = Plan.Select(p => p.Blocked).FirstOrDefault(b => b is not null) ?? "there is nothing in this commit to undo";
    }

    /// "Undo the ticked records": their inverse is staged for Review & commit. Nothing is written here.
    [Audited("config.undo.stage")]
    public async Task<IActionResult> OnPostUndoAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        try
        {
            var id = (Id ?? "").Trim();
            if (AuditScope.Current is { } a0) { a0.Target = "/Admin/Commits/commit/" + id; a0.Reason = Reason; }
            var why = (Reason ?? "").Trim();
            if (why.Length < ReasonMin) throw new ArgumentException($"say why it is undone (at least {ReasonMin} characters) -- it goes on the audit trail");
            await LoadCommitAsync(id, ct);
            if (Error is not null) throw new ArgumentException(Error);
            var chosen = Plan.Where(p => Pick.Contains(p.Row.JournalId)).ToList();
            if (chosen.Count == 0) throw new ArgumentException("tick at least one record to undo");
            if (chosen.FirstOrDefault(p => p.Blocked is not null) is { } bad) throw new ArgumentException($"{bad.Title} cannot be undone: {bad.Blocked}");
            var initiator = Rows.First().InitiatedBy;
            var staged = 0;
            foreach (var item in chosen)
            {
                var e = item.Entity!;
                // what the person sees now is what the commit must find at commit time (else: changed since -- refused there)
                var cur = await _applier.CurrentAsync(e.Name, item.Record!, ct);
                var change = ConfigRevertHandler.New(e, item.Op, item.Record!, cur.ContentSql, ConfigRevertHandler.SourceUndo, id, why, initiator);
                await _changes.StageAsync(User, change, ct);
                staged++;
            }
            if (AuditScope.Current is { } a) a.AfterJson = System.Text.Json.JsonSerializer.Serialize(new { commit = id, staged, records = chosen.Select(c => c.Title) });
            TempData["toast"] = $"{staged} record(s) of the commit staged for undo -- review them on Review & commit and commit there. Nothing has changed yet.";
            TempData["toastKind"] = "ok";
            return Redirect("/Changes");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException)
        {
            AuditScope.Current?.Refused(ex.Message);
            TempData["toast"] = "Not staged: " + ex.Message;
            TempData["toastKind"] = "error";
            return Redirect("/Admin/Commits?id=" + Uri.EscapeDataString(Id ?? ""));
        }
    }

    /// The journal source in words.
    public static string SourceWords(string source) => source switch
    {
        "gui" => "the web app", "api" => "the API", "import" => "an import / setup", "restore" => "a restore", "undo" => "an undo",
        "sync" => "a job / another system", "template" => "a template install", _ => source,
    };

    public static string OpWords(string op) => op switch { "Add" => "added", "Remove" => "removed", _ => "changed" };

    public string Link(int page, int? size = null) => "/Admin/Commits?" + string.Join("&", new[] { ("entity", Entity), ("q", Q), ("size", (size ?? PageSize) == SI.Management.Core.ProData.GridSql.DefaultPageSize ? null : (size ?? PageSize).ToString(CultureInfo.InvariantCulture)), ("p", page.ToString(CultureInfo.InvariantCulture)) }
        .Where(x => !string.IsNullOrEmpty(x.Item2)).Select(x => x.Item1 + "=" + Uri.EscapeDataString(x.Item2!)));
}
