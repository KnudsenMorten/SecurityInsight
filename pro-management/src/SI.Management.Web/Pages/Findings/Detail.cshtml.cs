using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Export;

namespace SI.Management.Web.Pages.Findings;

/// One finding: every field, its detail JSON rendered as a readable list, the asset's identifiers, the exemptions that
/// cover it -- and (Admin) the form that STAGES an exemption for it.
public sealed class DetailModel : PageModel
{
    private readonly IProDataQueries _q;
    private readonly ExemptionRepository _exemptions;
    private readonly ChangeService _changes;
    private readonly ILogger<DetailModel> _log;

    public DetailModel(IProDataQueries q, ExemptionRepository exemptions, ChangeService changes, ILogger<DetailModel> log)
    { _q = q; _exemptions = exemptions; _changes = changes; _log = log; }

    [BindProperty(SupportsGet = true)] public string? C { get; set; }
    [BindProperty(SupportsGet = true)] public string? Id { get; set; }

    public FindingDetail? Detail { get; private set; }
    public IReadOnlyList<(string Key, string Value)> Fields { get; private set; } = Array.Empty<(string, string)>();
    public IReadOnlyList<ExemptionRow> Covering { get; private set; } = Array.Empty<ExemptionRow>();
    public string? Query { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();

    [BindProperty] public string ExemptScope { get; set; } = ExemptionRepository.ScopeFinding;
    [BindProperty] public string? ExemptReason { get; set; }
    [BindProperty] public DateTime? ExemptUntil { get; set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Error is null ? NotFound() : Page();
        return Page();
    }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(Id)) return false;
        try
        {
            // #264: one finding is always shown -- exempted or not -- with its mark when the database carries it
            var schema = HttpContext?.RequestServices.GetService<SI.Management.Web.Exemptions.IExemptedSchema>();
            var ready = schema is not null && await schema.ReadyAsync(ct);
            SI.Management.Core.QueryResult<FindingDetail?> r;
            using (SI.Management.Core.ProData.Exempted.Use(ready ? SI.Management.Core.ProData.ExemptedScope.IncludeAll : null)) r = await _q.FindingAsync(C, Id, ct);
            Query = r.Query;
            Detail = r.Data;
            if (Detail is null) return false;
            Fields = Flatten(Detail.DetailJson);
            try
            {
                var f = Detail.Finding;
                Covering = (await _exemptions.ActiveAsync(f.AssetKey, 500, ct)).Rows
                    .Where(e => ExemptionRepository.Covers(e, f.AssetKey, f.ReportName, f.ConfigurationId, f.Cve)).ToList();
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "exemptions could not be read"); }
            await LoadGovernanceAsync(Detail.Finding, ct);
            await LoadLinksAsync(Detail.Finding, ct);
            return true;
        }
        catch (ArgumentException ex) { Error = ex.Message; return false; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading a finding failed");
            Error = "The finding could not be read: " + ex.Message;
            return false;
        }
    }

    [SI.Management.Web.Audit.Audited("exemption.finding.stage")]
    public async Task<IActionResult> OnPostExemptAsync(CancellationToken ct)
    {
        if (!User.MayChange()) return Forbid();
        if (!await LoadAsync(ct)) return Error is null ? NotFound() : Page();
        var f = Detail!.Finding;
        // role + scope (#253), server-side: a Delegated user only inside their scopes (403, nothing staged)
        var target = ChangeAccess.ForFinding(f, ExemptScope);
        var gate = HttpContext.RequestServices.GetRequiredService<IAccessScope>().Can(User, AccessAction.Exempt, target);
        if (!gate.Allowed) return AccessResults.Refused(Request, gate);
        var req = new ExemptionRequest(ExemptScope, Blank(f.ReportName), Blank(f.Cve) is null ? Blank(f.ConfigurationId) : null, Blank(f.Cve),
            ExemptScope == ExemptionRepository.ScopeIssue ? null : f.AssetKey, f.AssetName, ExemptReason ?? "",
            ExemptUntil is { } u ? DateTime.SpecifyKind(u.Date.AddDays(1).AddSeconds(-1), DateTimeKind.Utc) : null, Blank(f.SecurityDomain));
        var (change, why) = _changes.NewExemption(req);
        if (change is null) { Problems = why; return Page(); }
        await _changes.StageAsync(User, ChangeAccess.Stamp(change, target), ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        return RedirectToPage(new { c = C, id = Id });
    }

    /// Excel workbook of this finding: its fields and detail, the asset's identifiers, the exemptions that cover it.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Error is null ? NotFound() : BadRequest(Error);
        var d = Detail!;
        var f = d.Finding;
        return await ExcelExport.FileAsync("finding", f.CollectionId, (x, info) =>
        {
            info.Collection = f.CollectionId;
            info.Add("Finding", f.FindingId);
            var fields = new List<object?[]>
            {
                new object?[] { "Finding", "Title", f.Title }, new object?[] { "Finding", "Asset", f.AssetName },
                new object?[] { "Finding", "Asset kind", f.AssetKind }, new object?[] { "Finding", "Asset key", f.AssetKey },
                new object?[] { "Finding", "Asset tier", ExcelExport.Tier(f.Tier) }, new object?[] { "Finding", "Report", f.ReportName },
                new object?[] { "Finding", "Security domain", f.SecurityDomain }, new object?[] { "Finding", "CVE", ExcelExport.Blank(f.Cve) },
                new object?[] { "Finding", "Configuration", ExcelExport.Blank(f.ConfigurationId) }, new object?[] { "Finding", "Severity", f.Severity },
                new object?[] { "Finding", "Risk Score", f.RiskScore }, new object?[] { "Finding", "Collection time", f.CollectionTime },
                new object?[] { "Finding", "Collection", f.CollectionId }, new object?[] { "Finding", "Finding id", f.FindingId },
            };
            fields.AddRange(Fields.Select(kv => new object?[] { "Detail", kv.Key, kv.Value }));
            if (d.AssetPropertiesJson is { Length: > 0 } props) fields.Add(new object?[] { "Asset", "Properties (JSON)", props });
            x.Sheet(info, "Finding", new[] { "Section", "Field", "Value" }, fields);
            x.Sheet(info, "Asset identifiers", new[] { "Asset", "Identifier type", "Identifier" },
                d.Identifiers.Select(i => new object?[] { f.AssetName, i.Item1, i.Item2 }));
            x.Sheet(info, "Exemptions", new[] { "Scope", "Reason", "Report", "CVE", "Configuration", "Asset key", "Created by", "Created", "Expires" },
                Covering.Select(e => new object?[] { e.Scope, e.Reason, e.ReportName, e.Cve, e.ConfigurationId, e.AssetKey, e.CreatedBy, e.CreatedAt, e.ExpiresAt }));
            return Task.CompletedTask;
        }, ct);
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;

    // ---------------------------------------------------------------- #693 the findings this one is linked with

    /// The links this finding is in (active first, then the undone ones as history); empty when there is none or the
    /// database does not record them yet.
    public IReadOnlyList<FindingLink> Links { get; private set; } = Array.Empty<FindingLink>();
    /// The CI Risk Analysis keyed this finding on (null = not recorded yet: linking is offered after the next run).
    public string? LinkOwner { get; private set; }
    [BindProperty] public string? LinkId { get; set; }
    [BindProperty] public string? UnlinkReason { get; set; }

    private async Task LoadLinksAsync(FindingRow f, CancellationToken ct)
    {
        if (HttpContext?.RequestServices.GetService(typeof(FindingLinks)) is not FindingLinks links) return;
        try
        {
            var owners = await links.OwnersAsync(f.CollectionId, new[] { f.FindingId }, ct);
            LinkOwner = owners is not null && owners.TryGetValue(f.FindingId, out var o) ? o : null;
            Links = await links.ForFindingAsync(LinkOwner, FindingLinks.KeyOf(f.ConfigurationId, f.Cve), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the finding's links could not be read"); }
    }

    /// Admin only: undo a link (the link is kept as history, marked not used, with who, when and why). The findings are
    /// separate again from the next Risk Analysis run.
    [SI.Management.Web.Audit.Audited("finding.link.remove")]
    public async Task<IActionResult> OnPostUnlinkAsync(CancellationToken ct)
    {
        var gate = HttpContext.RequestServices.GetRequiredService<IAccessScope>().Can(User, AccessAction.Administer);
        if (!gate.Allowed) return AccessResults.Refused(Request, gate);
        if (!await LoadAsync(ct)) return Error is null ? NotFound() : Page();
        var links = HttpContext.RequestServices.GetRequiredService<FindingLinks>();
        var mine = Links.FirstOrDefault(l => l.Id == LinkId && l.Active);
        if (mine is null) { TempData["toast"] = "Not unlinked: this finding is not in that link."; TempData["toastKind"] = "error"; return RedirectToPage(new { c = C, id = Id }); }
        var r = await links.UnlinkAsync(mine.Id, UnlinkReason ?? "", User.ChangeName(), ct);
        TempData["toast"] = r.Status == SI.Management.Web.Settings.WriteStatus.Saved
            ? $"Unlinked: the {mine.Members.Count} findings of {mine.Id} are separate again from the next Risk Analysis run (the link is kept as history)."
            : "Not unlinked: " + r.Message;
        TempData["toastKind"] = r.Status == SI.Management.Web.Settings.WriteStatus.Saved ? "ok" : "error";
        return RedirectToPage(new { c = C, id = Id });
    }

    /// The finding's ONE thread (#265): its governance log and status (#254), its comments / recommendations / approvals
    /// (#258) and its follow-up tasks -- for everyone who may see the finding (the department scope decides; a finding
    /// outside a department-limited user's departments shows no thread).
    public SI.Management.Web.Tasks.FindingThreadView? Thread { get; private set; }

    private async Task LoadGovernanceAsync(FindingRow f, CancellationToken ct)
    {
        if (HttpContext?.RequestServices.GetService(typeof(SI.Management.Web.Tasks.FindingThreadService)) is not SI.Management.Web.Tasks.FindingThreadService threads) return;
        if (GovernanceKeys.Recommendation(f.ConfigurationId, f.Cve) is null || string.IsNullOrWhiteSpace(f.AssetKey)) return;
        try
        {
            var here = "/Findings/Detail?c=" + Uri.EscapeDataString(f.CollectionId) + "&id=" + Uri.EscapeDataString(f.FindingId);
            Thread = await threads.LoadAsync(User, await threads.TargetAsync(f, ct), here, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the finding's thread could not be read"); }
    }

    /// The detail JSON as (key, value) rows: top-level scalars as text, nested objects/arrays as compact JSON, empty
    /// values skipped. Invalid JSON is shown as one raw row.
    public static IReadOnlyList<(string Key, string Value)> Flatten(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<(string, string)>();
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Object) return new[] { ("(detail)", d.RootElement.GetRawText()) };
            return d.RootElement.EnumerateObject()
                .Select(p => (p.Name, p.Value.ValueKind switch
                {
                    JsonValueKind.String => p.Value.GetString() ?? "",
                    JsonValueKind.Null or JsonValueKind.Undefined => "",
                    _ => p.Value.GetRawText(),
                }))
                .Where(x => x.Item2.Length > 0 && x.Item2 != "[]" && x.Item2 != "{}")
                .ToList();
        }
        catch (JsonException) { return new[] { ("(detail, not JSON)", json) }; }
    }
}
