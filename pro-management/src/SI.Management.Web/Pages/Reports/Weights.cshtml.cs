using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Reports;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// The Weights editor (#275 G7): the weighted risk factors (riskscore_weighted, weightedRiskFactors) per engine -- for the
/// whole solution (cfg.Document weights/solution) or for one report (cfg.ItemOverride weights/report/&lt;R&gt;, which beats
/// the solution's) -- as a grid: per engine the combine mode and the cap, per field its value -> multiplier map and default,
/// validated by the same rules as the engine (DocumentValidator, Test-SIProDocument). The other sections of a weights file
/// (the risk-model mappers, item weights/model) are shown read-only: Risk Analysis v3 reads only weightedRiskFactors.
/// Staged: the solution's through THE document change, a report's through the report designer's change.
/// </summary>
public sealed class WeightsModel : ReportsPage
{
    private readonly DocumentRepository _documents;
    public WeightsModel(IReportStore store, ChangeService changes, DocumentRepository documents, ILogger<WeightsModel> log) : base(store, changes, log) => _documents = documents;

    public sealed class FieldForm { public string? Field { get; set; } public string? Default { get; set; } public string? Map { get; set; } }
    public sealed class EngineForm { public string? Engine { get; set; } public string? Combine { get; set; } public string? Max { get; set; } public List<FieldForm> Fields { get; set; } = new(); }

    [BindProperty(SupportsGet = true)] public string? Scope { get; set; }
    [BindProperty] public List<EngineForm> E { get; set; } = new();

    public string? CurrentBody { get; private set; }
    public long? DocumentVersion { get; private set; }
    public string? ModelBody { get; private set; }
    public bool IsSolution => (Scope ?? "solution") == "solution";
    public IEnumerable<string> ReportNames => State?.Reports.Where(r => r.Origin != ReportOrigin.Own).Select(r => r.Name) ?? Enumerable.Empty<string>();

    private async Task<bool> PrepareAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return false;
        Scope = string.IsNullOrWhiteSpace(Scope) ? "solution" : Scope.Trim();
        if (!IsSolution && !(Scope.StartsWith("report/", StringComparison.Ordinal) && ReportNames.Contains(Scope[7..], StringComparer.Ordinal))) { Messages.Add($"Not found: '{Scope}' is not the solution or a vendor report"); Scope = "solution"; }
        try
        {
            if (IsSolution) { var d = await _documents.ReadAsync("weights", "solution", ct); CurrentBody = d?.Body; DocumentVersion = d?.Version; }
            else CurrentBody = State!.Weights.TryGetValue(Scope, out var w) && w.State == "override" ? w.Body : null;
            ModelBody = State!.Weights.TryGetValue("model", out var m) && m.State == "override" ? m.Body : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogError(ex, "weights"); Error = "The weights could not be read: " + ex.Message; return false; }
        return true;
    }

    /// The grid as the form shows it: every engine, its fields plus one empty row to add a field.
    public static List<EngineForm> FormOf(IReadOnlyList<WeightEngine> engines) => DocumentValidator.WeightEngines.Select(name =>
    {
        var e = engines.FirstOrDefault(x => x.Engine == name);
        var f = new EngineForm { Engine = name, Combine = e?.Combine ?? "", Max = e?.MaxMultiplier ?? "" };
        if (e is not null) f.Fields.AddRange(e.Fields.Select(x => new FieldForm { Field = x.Field, Default = x.Default, Map = string.Join("\n", x.Map.Select(kv => kv.Value + " = " + kv.Multiplier)) }));
        f.Fields.Add(new FieldForm());
        return f;
    }).ToList();

    public static IReadOnlyList<WeightEngine> EnginesOf(IEnumerable<EngineForm> form) => form.Where(e => DocumentValidator.WeightEngines.Contains(e.Engine ?? "")).Select(e => new WeightEngine(e.Engine!, e.Combine ?? "", e.Max ?? "",
        e.Fields.Where(f => !string.IsNullOrWhiteSpace(f.Field)).Select(f => new WeightField(f.Field!.Trim(),
            (f.Map ?? "").Split('\n').Select(l => l.Split('=', 2)).Where(p => p.Length == 2 && p[0].Trim().Length > 0).Select(p => (p[0].Trim(), p[1].Trim())).ToList(), f.Default ?? "")).ToList())).ToList();

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!await PrepareAsync(ct)) return;
        E = FormOf(WeightsDocument.Read(CurrentBody));
    }

    [Audited("weights.document.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await PrepareAsync(ct)) return Page();
        var engines = EnginesOf(E);
        var empty = engines.All(e => e.Fields.Count == 0);
        var body = WeightsDocument.Write(CurrentBody, engines);
        if (CurrentBody is not null ? ProJson.Same(body, CurrentBody) : empty) { Messages.Add("Not staged: nothing changed -- these are the weights in force"); E = FormOf(engines); return Page(); }
        var why = empty ? new List<string>() : DocumentValidator.Validate("weights", "solution", body, Array.Empty<string>()).ToList();
        if (why.Count > 0) { Messages.AddRange(why.Select(w => "Not staged: " + w)); E = FormOf(engines); return Page(); }
        if (string.IsNullOrWhiteSpace(Reason) || Reason.Trim().Length < 3) { Messages.Add("Not staged: give a reason (at least 3 characters)"); E = FormOf(engines); return Page(); }
        if (IsSolution)
        {
            var (change, problems) = await Changes.NewDocumentAsync("weights", "solution", empty ? "Reset" : "Set", empty ? null : body, DocumentVersion, Reason, ct);
            if (change is null) { Messages.AddRange(problems.Select(w => "Not staged: " + w)); E = FormOf(engines); return Page(); }
            var pending = await Changes.PendingAsync(User, ct);
            var old = pending.Where(p => p.Kind == ChangeKinds.Document && p.Get("docKind") == "weights" && p.Get("docKey") == "solution").Select(p => p.Id).ToList();
            if (old.Count > 0) await Changes.DiscardAsync(User, old, ct);
            await Changes.StageAsync(User, change, ct);
            TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
            TempData["toastKind"] = "ok";
            return RedirectToPage("/Changes/Index");
        }
        State!.Weights.TryGetValue(Scope!, out var cur);
        var w = ItemWrites.For("weights", Scope!, null, cur.State, cur.Body, empty ? null : body, true,
            empty ? "back to the solution's weights" : string.Join("; ", engines.Where(e => e.Fields.Count > 0).Select(e => $"{e.Engine}: {string.Join(", ", e.Fields.Select(f => f.Field))}")));
        var staged = await StageAsync(ReportChanges.Weights, $"Weights of report {Scope![7..]}", w is null ? Array.Empty<ItemWrite>() : new[] { w }, ct);
        if (staged is not null) return staged;
        E = FormOf(engines);
        return Page();
    }
}
