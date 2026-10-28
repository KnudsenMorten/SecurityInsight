using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Cis;

/// <summary>
/// #462 Manual overrides on CIs (readers see them; every change checks Admin itself). An Admin sets a field of one CI by
/// hand -- tier, purpose, category, department or a CMDB field -- with a reason and an optional expiry; changes it; or
/// removes it (soft: the row stays with who removed it and when). Nothing is written here: each change is staged on
/// Review &amp; commit (CiOverrideChanges) and written in the signed-in name with its change-log row. The next CI build applies
/// the overrides in force over the rules (the CI then shows the value as set by an override, with who, why and until);
/// an expired override is shown as expired and no longer wins.
/// </summary>
public sealed class OverridesModel : PageModel
{
    private readonly CiOverrideStore _store;
    private readonly CiOverrideChanges _changes;
    private readonly ChangeService _service;
    private readonly ILogger<OverridesModel> _log;

    public OverridesModel(CiOverrideStore store, CiOverrideChanges changes, ChangeService service, ILogger<OverridesModel> log)
    { _store = store; _changes = changes; _service = service; _log = log; }

    /// Filter / prefill: one CI.
    [BindProperty(SupportsGet = true)] public string? Ci { get; set; }
    /// Prefill the form from this override (edit).
    [BindProperty(SupportsGet = true)] public long? Edit { get; set; }
    [BindProperty] public string? Field { get; set; }
    [BindProperty] public string? Value { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// The expiry as the date picker sends it (yyyy-MM-dd, the end of that day UTC); empty = no end.
    [BindProperty] public string? Expires { get; set; }

    public IReadOnlyList<CiOverrideRow> Rows { get; private set; } = Array.Empty<CiOverrideRow>();
    public CiOverrideRow? Editing { get; private set; }
    public bool TableMissing { get; private set; }
    public string? Error { get; private set; }
    public DateTime NowUtc { get; } = DateTime.UtcNow;

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            if (!await _store.TableExistsAsync(ct)) { TableMissing = true; return; }
            Rows = await _store.ListAsync(Ci, ct);
            if (Edit is { } id) Editing = Rows.FirstOrDefault(r => r.Id == id) ?? await _store.ReadAsync(id, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the manual CI overrides could not be read");
            Error = "The manual overrides could not be read from the Pro database: " + ex.Message;
        }
    }

    /// PURE. The picker's date (yyyy-MM-dd) as the end of that day in UTC; empty = no expiry; unreadable = an error.
    public static (DateTime? Value, string? Error) ParseExpiry(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (null, null);
        if (DateTime.TryParseExact(text.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d))
            return (DateTime.SpecifyKind(d.Date.AddDays(1).AddSeconds(-1), DateTimeKind.Utc), null);
        return (null, $"'{text}' is not a date (yyyy-MM-dd)");
    }

    /// Admin only: stage a new or changed override (it replaces the one in force for that field).
    [SI.Management.Web.Audit.Audited("cioverride.set.stage")]
    public async Task<IActionResult> OnPostSetAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (exp, expWhy) = ParseExpiry(Expires);
        if (expWhy is not null) return await StageAsync(null, new[] { expWhy }, ct);
        var (change, why) = await _changes.NewSetAsync(Ci, Field, Value, Reason, exp, ct);
        return await StageAsync(change, why, ct);
    }

    /// Admin only: stage the removal (soft) of one override.
    [SI.Management.Web.Audit.Audited("cioverride.remove.stage")]
    public async Task<IActionResult> OnPostRemoveAsync(long id, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (change, why) = await _changes.NewRemoveAsync(id, Reason, ct);
        return await StageAsync(change, why, ct);
    }

    private async Task<IActionResult> StageAsync(StagedChange? change, IReadOnlyList<string> why, CancellationToken ct)
    {
        if (change is not null)
        {
            await _service.StageAsync(User, change, ct);
            TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
            TempData["toastKind"] = "ok";
        }
        else
        {
            TempData["toast"] = "Not staged: " + string.Join("; ", why);
            TempData["toastKind"] = "error";
        }
        return RedirectToPage(new { ci = Ci });
    }

    /// The field in words.
    public static string FieldText(string field) => field switch
    {
        "si_tier" => "Tier",
        "si_purpose" => "Purpose",
        "si_category" => "Category",
        "si_department" => "Department",
        _ when field.StartsWith("si_cmdb_", StringComparison.Ordinal) => "CMDB " + field["si_cmdb_".Length..].Replace('_', ' '),
        _ => field,
    };

    public static string Badge(string state) => state switch { "active" => "good", "expired" => "warn", _ => "bad" };
}
