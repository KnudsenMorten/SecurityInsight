using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Admin.Settings;

/// One cfg.Document: its text, checked by the run-start rules on "Check", and STAGED (set or remove) for Review &amp;
/// commit. The version read when the page opened travels with the change, so a document that moved since is refused.
public sealed class DocumentModel : PageModel
{
    private readonly DocumentRepository _docs;
    private readonly ChangeService _changes;
    public DocumentModel(DocumentRepository docs, ChangeService changes) { _docs = docs; _changes = changes; }

    [BindProperty(SupportsGet = true)] public string? Kind { get; set; }
    [BindProperty(SupportsGet = true)] public string? Key { get; set; }
    [BindProperty] public string? Body { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public long? ReadVersion { get; set; }

    public DocumentRow? Current { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public bool Checked { get; private set; }
    public string? KeyProblem { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        Body = Current?.Body ?? Template(Kind!, Key!);
        ReadVersion = Current?.Version;
        return Page();
    }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        Kind = Kind?.Trim(); Key = Key?.Trim();
        KeyProblem = DocumentValidator.KeyProblem(Kind ?? "", Key ?? "");
        if (KeyProblem is not null) return false;
        Current = await _docs.ReadAsync(Kind!, Key!, ct);
        return true;
    }

    [SI.Management.Web.Audit.NotAudited("a check: validates the document and stages and writes nothing")]
    public async Task<IActionResult> OnPostCheckAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        Problems = DocumentRepository.Validate(new DocumentWrite(Kind!, Key!, "Set", Body, ReadVersion, Reason), await _changes.KnownReportsAsync(ct));
        Checked = true;
        return Page();
    }

    [SI.Management.Web.Audit.Audited("settings.document.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct) => await StageAsync("Set", ct);
    [SI.Management.Web.Audit.Audited("settings.document.stage-reset")]
    public async Task<IActionResult> OnPostRemoveAsync(CancellationToken ct) => await StageAsync("Reset", ct);

    private async Task<IActionResult> StageAsync(string action, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if ((Current?.Version) != ReadVersion)
        {
            Problems = new[] { "This document changed since you opened it. Reload it and make the change again." };
            return Page();
        }
        var (c, why) = await _changes.NewDocumentAsync(Kind!, Key!, action, action == "Reset" ? null : Body, ReadVersion, Reason, ct);
        if (c is null) { Problems = why; Checked = true; return Page(); }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: " + c.Title + ". Nothing is written until you review and commit.";
        return Redirect("/Changes");
    }

    /// A starting text for a new document -- one the validator accepts, so "Check" on an untouched template passes.
    public static string Template(string kind, string key) => kind switch
    {
        "exclusions" when key == "global" => "{\n  \"_note\": \"asset tags excluded from every report\",\n  \"ExcludedAssetTags\": []\n}",
        "exclusions" => "{\n  \"_note\": \"exclusions for " + key + "\",\n  \"ExcludedCves\": [],\n  \"ExcludedConfigurationIds\": [],\n  \"ExcludedAssetTags\": []\n}",
        "weights" => "{\n  \"weightedRiskFactors\": {\n    \"endpoint\": {\n      \"combine\": \"product\",\n      \"fields\": [ { \"field\": \"Tier\", \"valueMap\": { \"0\": 150, \"1\": 125 }, \"default\": 100 } ]\n    }\n  }\n}",
        "rule" => NewRule(key),
        OwnershipMapValidator.Kind => OwnershipMapValidator.Starter,
        _ => "",
    };

    private static string NewRule(string key)
    {
        var engine = key[..key.IndexOf('/')];
        var id = key[(key.IndexOf('/') + 1)..];
        var applies = engine == "shared" ? "any" : engine;
        return string.Join("\n", new[]
        {
            RuleTemplates.Marker + " -- a rule of this installation.", "id: " + id, "appliesTo: " + applies, "mode: append",
            "purpose: 'Describe what this rule finds'", "category: 'Custom'", "description: ''", "", "detections:", "  - id: " + id,
            "    detect:", "      any:", "        - kind: nameMatches", "          namePatterns:", "            - '(?i)^example-'",
            "    set:", "      Tier: 3", "      Purpose: 'Describe what this rule finds'", "      Category: 'Custom'", "",
        });
    }

    /// #251: the CMDB ownership map (configuration, kept in cfg.ItemOverride) rather than a cfg.Document.
    public bool IsOwnershipMap => OwnershipMapValidator.Is(Kind, Key);

    public string VersionText => ReadVersion?.ToString(CultureInfo.InvariantCulture) ?? "";
}
