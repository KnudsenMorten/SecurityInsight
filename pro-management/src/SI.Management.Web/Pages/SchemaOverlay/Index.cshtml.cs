using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.SchemaOverlay;

/// <summary>
/// Configuration > Schema overlays (#275 G12): per profiling engine, the profile columns, contributors and raw-payload
/// paths you add to (or change in) the shipped profile table -- v2.2's asset-profiling-schema\&lt;engine&gt;.schema.custom.json.
/// Readers see them; an Admin opens an engine to edit its overlay.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly SchemaOverlayStore _store;
    private readonly ILogger<IndexModel> _log;
    public IndexModel(SchemaOverlayStore store, ILogger<IndexModel> log) { _store = store; _log = log; }

    public bool Schema { get; private set; }
    public IReadOnlyList<SchemaOverlayEntry> Overlays { get; private set; } = Array.Empty<SchemaOverlayEntry>();
    public string? Error { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { (Schema, Overlays) = await _store.LoadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the schema overlays could not be read");
            Error = "The schema overlays could not be read from the Pro database: " + ex.Message;
        }
    }

    /// The engines that have an overlay (owner 2026-10-19, "what is this - shows 0, is that bad": rows of zeros are not shown).
    public IReadOnlyList<SchemaOverlayEntry> WithOverlay => Overlays.Where(o => o.Body is not null).ToList();

    /// <summary>
    /// Whether the "2.2 file" column means anything here. The app holds no install-wide "came from v2.2" mark, and the web
    /// app cannot see the v2.2 folder; the one record it has is who wrote an overlay -- the v2.2 import writes it as
    /// "migration" / "v2.2". So the column shows only when an overlay was written by that import.
    /// </summary>
    public bool ShowV22File => WithOverlay.Any(FromV22);

    public static bool FromV22(SchemaOverlayEntry o) =>
        o.Body is not null && o.UpdatedBy is { Length: > 0 } by
        && (by.Contains("migration", StringComparison.OrdinalIgnoreCase) || by.Contains("2.2", StringComparison.Ordinal));

    public static (int Fields, int Contributors, int Sources) Counts(string? body)
    {
        var f = OverlayFormModel.CannotShow(body) is null ? OverlayFormModel.From(body) : new OverlayFormModel();
        return (f.Fields.Count, f.Contributors.Count, f.Sources.Count);
    }
}
