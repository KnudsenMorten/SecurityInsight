using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.RiskIndex;

namespace SI.Management.Web.Pages.RiskIndex;

/// <summary>
/// Admin > Risk index (#266): the rows Risk Analysis scores every finding with, in the order it checks them -- FIRST MATCH
/// WINS, per score. Readers see it read-only (and can export it); an Admin edits it in the table (add, delete, duplicate,
/// move, inline edit, reset a row to the vendor's), imports (SI-keyed, or the 2.2 columns translated) / exports the CSV, sorts by specificity, runs
/// the dry run over current findings and stages the result for Review &amp; commit. Nothing is written on this page.
/// The edited rows travel in the form as JSON (the draft); the server validates, previews and stages them.
/// </summary>
public sealed class IndexModel : PageModel
{
    public const int SampleSize = 5000;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly IRiskIndexStore _store;
    private readonly RiskIndexChanges _changes;
    private readonly ChangeService _changeService;
    private readonly IStagingStore _staging;
    private readonly ILogger<IndexModel> _log;

    private readonly RiskFactorStore _dataModel;

    public IndexModel(IRiskIndexStore store, RiskIndexChanges changes, ChangeService changeService, IStagingStore staging, RiskFactorStore dataModel, ILogger<IndexModel> log)
    { _store = store; _changes = changes; _changeService = changeService; _staging = staging; _dataModel = dataModel; _log = log; }

    /// The draft: the edited rows, in order, as JSON (the browser's table writes it back on every action).
    [BindProperty] public string? Draft { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public IFormFile? Upload { get; set; }

    public RiskIndexState? State { get; private set; }
    public IReadOnlyList<RiskIndexRow> Rows { get; private set; } = Array.Empty<RiskIndexRow>();
    /// Per row of <see cref="Rows"/>: the item key it came from (the vendor row "reset to template" goes back to).
    public IReadOnlyList<string> Sources { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<RiskIndexIssue> Issues { get; private set; } = Array.Empty<RiskIndexIssue>();
    public RiskIndexPreview? Preview { get; private set; }
    public IReadOnlyList<string> Messages { get; private set; } = Array.Empty<string>();
    public bool SchemaMissing { get; private set; }
    public bool Edited { get; private set; }
    public string? Error { get; private set; }

    public sealed record DraftRow(RiskIndexRow Row, string Src);

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return;
        UseCommitted();
        Issues = RiskIndexEditor.Validate(Rows);
    }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        try
        {
            if (!await _store.SchemaAsync(ct)) { SchemaMissing = true; return false; }
            State = await _store.LoadAsync(ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the risk index could not be read");
            Error = "The risk index could not be read from the Pro database: " + ex.Message;
            return false;
        }
    }

    private void UseCommitted()
    {
        if (State is null) return;
        if (State.HasOrder)
        {
            Rows = State.Items.Select(i => i.Row).ToList();
            Sources = State.Items.Select(i => i.Key).ToList();
        }
        else
        {
            Rows = State.Ordered;
            Sources = RiskIndexEditor.Keys(Rows);
        }
    }

    /// The draft from the form (null + a message when it cannot be read).
    private IReadOnlyList<DraftRow>? ReadDraft()
    {
        try
        {
            var d = JsonSerializer.Deserialize<List<DraftRow>>(Draft ?? "[]", Json);
            if (d is null) return null;
            if (d.Count > RiskIndexEditor.MaxRows) { Messages = new[] { $"at most {RiskIndexEditor.MaxRows} rows" }; return null; }
            return d.Select(x => new DraftRow(Clean(x.Row ?? new RiskIndexRow()), x.Src ?? "")).ToList();
        }
        catch (JsonException) { Messages = new[] { "the edited rows could not be read -- reload the page" }; return null; }
    }

    private static RiskIndexRow Clean(RiskIndexRow r) =>
        RiskIndexColumns.All.Aggregate(r, (acc, c) => acc.With(c, acc.Get(c) ?? ""));

    private void UseDraft(IReadOnlyList<DraftRow> d)
    {
        Rows = d.Select(x => x.Row).ToList();
        Sources = d.Select(x => x.Src).ToList();
        Edited = true;
    }

    /// An Admin may change the index once it is editable (RiskIndexState.Editable): the vendor's rows are ordered, or every
    /// row in force already has its place.
    private bool MayEdit => User.IsAdmin() && State is { Editable: true };

    /// "Edit" at the top of the table opens the edit mode (?edit=1); every post is an edit action and stays in it.
    private bool EditRequested => Request.Query["edit"].ToString() is "1" or "true";

    /// Validate the draft and run the dry run over current findings.
    [SI.Management.Web.Audit.Audited("riskindex.draft.check")]
    public async Task<IActionResult> OnPostCheckAsync(CancellationToken ct)
    {
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit) audit.WhatIf = true;   // a dry run: never read as a change
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var d = ReadDraft();
        if (d is null) { UseCommitted(); return Page(); }
        UseDraft(d);
        Issues = RiskIndexEditor.Validate(Rows);
        try
        {
            var sample = await _store.SampleAsync(SampleSize, ct);
            Preview = RiskIndexDryRun.Compute(State!.Ordered, Rows, sample, await _dataModel.BandsAsync(ct));   // the rating bands in force (risk_rating_bands)
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the risk index dry run could not read findings");
            Messages = new[] { "The dry run could not read the current findings: " + ex.Message };
        }
        return Page();
    }

    /// Sort the draft by specificity (stable).
    [SI.Management.Web.Audit.Audited("riskindex.draft.sort")]
    public async Task<IActionResult> OnPostSortAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var d = ReadDraft();
        if (d is null) { UseCommitted(); return Page(); }
        var sorted = d.Select((x, i) => (x, i)).OrderBy(z => RiskIndexEditor.Specificity(z.x.Row)).ThenBy(z => z.i).Select(z => z.x).ToList();
        UseDraft(sorted);
        Issues = RiskIndexEditor.Validate(Rows);
        Messages = new[] { "Sorted by specificity: the most specific rows first; rows of equal specificity kept their order. Check the dry run before you stage it." };
        return Page();
    }

    /// Import a CSV (v2.2 or v3) into the draft. A v2.2 file is put in precedence order with the same scores.
    [SI.Management.Web.Audit.Audited("riskindex.draft.import")]
    public async Task<IActionResult> OnPostImportAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        if (Upload is null || Upload.Length == 0) { Messages = new[] { "choose a CSV file to import" }; UseFromDraftOrCommitted(); return Page(); }
        if (Upload.Length > 2_000_000) { Messages = new[] { "the file is larger than 2 MB" }; UseFromDraftOrCommitted(); return Page(); }
        string text;
        using (var r = new StreamReader(Upload.OpenReadStream(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true)) text = await r.ReadToEndAsync(ct);
        var parsed = RiskIndexCsv.Parse(text);
        if (parsed.Problems.Count > 0) { Messages = parsed.Problems.Select(p => "Not imported: " + p).Concat(parsed.Notes).ToList(); UseFromDraftOrCommitted(); return Page(); }
        // a file with the 2.2 columns arrives translated to the SI keys, in first-match order (RiskIndexV22); an SI file
        // without a Precedence column keeps its file order
        var ordered = parsed.HasPrecedenceColumn ? RiskIndexScoring.Ordered(parsed.Rows) : parsed.Rows;
        var keys = RiskIndexEditor.Keys(ordered);
        UseDraft(ordered.Select((row, i) => new DraftRow(row, keys[i])).ToList());
        Issues = RiskIndexEditor.Validate(Rows);
        Messages = new[] { parsed.FromV22
                ? $"Imported an index written with the 2.2 columns: it is shown as {ordered.Count} row(s) keyed by the SI fields, in first-match order, every base value carried over. Nothing is saved until you stage it and commit."
                : $"Imported {ordered.Count} row(s) in their order. Nothing is saved until you stage it and commit." }
            .Concat(parsed.Notes).ToList();
        return Page();
    }

    private void UseFromDraftOrCommitted()
    {
        var d = string.IsNullOrWhiteSpace(Draft) ? null : ReadDraft();
        if (d is not null) UseDraft(d); else UseCommitted();
        Issues = RiskIndexEditor.Validate(Rows);
    }

    /// Stage the draft for Review & commit (replaces a risk index change already pending).
    [SI.Management.Web.Audit.Audited("riskindex.index.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var d = ReadDraft();
        if (d is null) { UseCommitted(); return Page(); }
        UseDraft(d);
        var (change, why) = await _changes.NewAsync(Rows, Reason, ct);
        if (change is null)
        {
            Issues = RiskIndexEditor.Validate(Rows);
            Messages = why.Select(w => "Not staged: " + w).ToList();
            return Page();
        }
        var pending = await _staging.ListAsync(User, ct);
        var old = pending.Where(p => p.Kind == RiskIndexChanges.ChangeKind).Select(p => p.Id).ToList();
        if (old.Count > 0) await _changeService.DiscardAsync(User, old, ct);
        await _changeService.StageAsync(User, change, ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }

    /// The committed index as CSV (the SI columns, plus Precedence): what Risk Analysis reads on its next run.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return NotFound();
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(RiskIndexCsv.Write(State!.Ordered))).ToArray(), "text/csv", "riskscore.index.custom.csv");
    }

    /// The draft as CSV (export before staging).
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnPostExportAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var d = ReadDraft();
        if (d is null) { UseCommitted(); return Page(); }
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(RiskIndexCsv.Write(d.Select(x => x.Row).ToList()))).ToArray(), "text/csv", "riskscore.index.edited.csv");
    }

    /// The draft as the browser's table reads it: rows with their source key, the vendor rows by key.
    public string DraftJson() => JsonSerializer.Serialize(Rows.Select((r, i) => new DraftRow(r, i < Sources.Count ? Sources[i] : "")), Json);
    public string TemplatesJson() => JsonSerializer.Serialize(State?.Templates ?? new Dictionary<string, RiskIndexRow>(), Json);
    public bool CanEdit => MayEdit;
    /// The table is in edit mode: inline fields, Add row / Up / Down / Duplicate / Reset / Delete and Stage.
    public bool Editing => MayEdit && (EditRequested || HttpMethods.IsPost(Request.Method));
    /// Why an Admin cannot edit here (null for a reader, or when editing is available) -- shown at the top with what to do.
    public string? EditBlocked => User.IsAdmin() && State is { Editable: false } s ? s.NotEditableReason : null;

    /// Where a row comes from, against the vendor template of its source key.
    public string OriginOf(int i)
    {
        if (State is null || i >= Rows.Count) return "";
        var src = i < Sources.Count ? Sources[i] : "";
        if (!State.Templates.TryGetValue(src, out var t)) return "yours";
        return t.SameContent(Rows[i]) ? "vendor" : "changed";
    }
}
