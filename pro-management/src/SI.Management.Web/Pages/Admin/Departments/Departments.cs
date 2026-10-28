using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Departments;

/// <summary>
/// Admin &gt; Departments (#254): the departments, their people (technical owners, business owners, approvers, delegates,
/// advisors), the department rules and the overrides. Every change is written at once, in one transaction with its
/// cfg.ChangeLog row (Admin &gt; Change history shows it); the data sync applies it on its next run.
/// </summary>
public abstract class DepartmentAdminModel : PageModel
{
    protected readonly DepartmentRepository Repo;
    protected readonly ILogger Log;
    protected DepartmentAdminModel(DepartmentRepository repo, ILogger log) { Repo = repo; Log = log; }

    public string? Error { get; protected set; }
    public bool Ready { get; private set; }

    /// False (with the setup step in Error) when the Pro database does not have the department tables yet.
    protected async Task<bool> ReadyAsync(CancellationToken ct)
    {
        try
        {
            Ready = await Repo.TablesExistAsync(ct);
            if (!Ready) Error = "The Pro database does not have the department tables yet: apply the Pro settings schema again (sql\\si-pro-settings.sql; it only adds).";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogError(ex, "department tables");
            Error = "The Pro database could not be read: " + ex.Message;
        }
        return Ready;
    }

    /// <summary>
    /// #335: a refused or failed write is NEVER only a toast that fades. Besides the toast, the message comes back as
    /// <see cref="Refusal"/>, which the page shows as a notice that stays until the next change.
    /// </summary>
    protected IActionResult Done(WriteResult r, string page, object? routeValues = null)
    {
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        if (r.Status != WriteStatus.Saved) TempData[RefusalKey] = r.Message;
        return RedirectToPage(page, routeValues);
    }

    public const string RefusalKey = "deptRefusal";
    public const string LostPostText = "Nothing was saved: the form reached the app after your sign-in had to be renewed (this happens right after the app is updated), so what you typed was lost. Enter it again.";

    /// The refusal of the last write on this page (kept until shown), or -- when the browser came back here by GET on a
    /// form's handler -- that the post was lost on the way (a renewed sign-in replays the URL, never the form).
    public string? Refusal { get; protected set; }

    protected void ReadRefusal()
    {
        Refusal = TempData[RefusalKey] as string;
        if (Refusal is null && HttpMethods.IsGet(Request.Method) && !string.IsNullOrEmpty(Request.Query["handler"])) Refusal = LostPostText;
    }

    /// A write that throws (a database that refuses it, a lost connection) answers as a refusal with the reason -- the
    /// page says so instead of an error page, and nothing is half-written (every write is one transaction).
    protected async Task<WriteResult> Safely(Func<Task<WriteResult>> write, string what)
    {
        try { return await write(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogError(ex, "{What} failed", what);
            return new WriteResult(WriteStatus.Refused, $"{what} could not be saved -- the Pro database answered: {ex.Message}");
        }
    }
}

// ---- the people table (#335): the same on the New department form and on a department's page ------------------------

/// What the people table partial renders: its rows (kept and new), the role choices, whether people are looked up in
/// the directory, the URL the picker asks for suggestions.
public sealed record PeopleTableModel(IReadOnlyList<PeopleRow> Rows, IReadOnlyList<DepartmentMemberRow> Existing, string SearchUrl, bool DirectoryOn);

public abstract class DepartmentPeopleModel(DepartmentRepository repo, DepartmentPeopleResolver resolver, ILogger log) : DepartmentAdminModel(repo, log)
{
    protected DepartmentPeopleResolver Resolver => resolver;
    public bool DirectoryOn => resolver.DirectoryOn;

    /// The rows the people table shows: as posted when a save was refused (nothing has to be typed again).
    public List<PeopleRow> Rows { get; protected set; } = new();

    /// The people picker: suggestions for what was typed (JSON). Admin, like the page (the folder's policy).
    public async Task<IActionResult> OnGetPeopleAsync(string? q, CancellationToken ct) =>
        new JsonResult((await resolver.SearchAsync(q, ct)).Select(s => new { value = s.Value, label = s.Label, type = s.Type }));

    /// The existing people as rows, plus one blank row to add someone (more with "+ Add person").
    protected static List<PeopleRow> RowsOf(IEnumerable<DepartmentMemberRow> people) =>
        [.. people.Select(p => new PeopleRow { MemberId = p.MemberId, Person = p.Mail ?? p.ObjectId, Role = p.Role }), new PeopleRow()];
}

// ---- the list + a new department ----------------------------------------------------------------------------------

public sealed class IndexModel(DepartmentRepository repo, DepartmentPeopleResolver resolver, ILogger<IndexModel> log) : DepartmentPeopleModel(repo, resolver, log)
{
    public IReadOnlyList<DepartmentRow> All { get; private set; } = Array.Empty<DepartmentRow>();
    public IReadOnlyList<DepartmentMemberRow> People { get; private set; } = Array.Empty<DepartmentMemberRow>();
    [BindProperty(SupportsGet = true)] public bool Retired { get; set; }

    /// What was typed on the New department form -- kept when the create is refused, so nothing has to be typed again.
    public NewDepartmentForm Form { get; private set; } = new();

    public async Task OnGetAsync(CancellationToken ct)
    {
        ReadRefusal();
        Rows = [new PeopleRow()];
        await LoadAsync(ct);
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        if (!await ReadyAsync(ct)) return;
        try
        {
            All = await Repo.ListAsync(Retired, ct);
            People = await Repo.MembersAsync(null, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogError(ex, "departments");
            Error = "The departments could not be read: " + ex.Message;
        }
    }

    public IEnumerable<DepartmentMemberRow> Of(int id) => People.Where(p => p.DepartmentId == id);

    /// <summary>
    /// Creates the department AND the people of its people table in ONE transaction. Saved: the department's page.
    /// Refused: THIS page again with the reason in a notice that stays and everything typed still in the form.
    /// </summary>
    [SI.Management.Web.Audit.Audited("department.department.create")]
    public async Task<IActionResult> OnPostCreateAsync(NewDepartmentForm form, List<PeopleRow>? rows, CancellationToken ct)
    {
        Form = form;
        Rows = rows is { Count: > 0 } ? rows : [new PeopleRow()];
        var (members, problems) = await Resolver.ResolveRowsAsync(0, Rows, Array.Empty<DepartmentMemberRow>(), ct);
        WriteResult r;
        int? id = null;
        if (problems.Count > 0) r = new WriteResult(WriteStatus.Refused, string.Join("; ", problems) + " -- nothing was written");
        else
        {
            (WriteResult Result, int? DepartmentId) saved = (new WriteResult(WriteStatus.Refused, ""), null);
            r = await Safely(async () => { saved = await Repo.SaveAsync(new DepartmentInput(null, form.Name ?? "", form.Mail, form.Description, form.MatchValues, null), members, User.ChangeName(), ct); return saved.Result; },
                "The department");
            id = saved.DepartmentId;
        }
        if (r.Status == WriteStatus.Saved && id is not null) return Done(r, "/Admin/Departments/Edit", new { id });
        // refused: the page again, the reason on it, the form as typed (the toast also tells the audit trail it was refused)
        Refusal = "The department was not created: " + r.Message;
        TempData["toast"] = Refusal;
        TempData["toastKind"] = "error";
        await LoadAsync(ct);
        return Page();
    }
}

/// The New department form's own fields (its people are the people table's rows).
public sealed class NewDepartmentForm
{
    public string? Name { get; set; }
    public string? Mail { get; set; }
    public string? Description { get; set; }
    public string? MatchValues { get; set; }
}

// ---- one department: its fields, its people, retire ---------------------------------------------------------------

public sealed class EditModel(DepartmentRepository repo, DepartmentPeopleResolver resolver, ILogger<EditModel> log) : DepartmentPeopleModel(repo, resolver, log)
{
    [BindProperty(SupportsGet = true)] public int Id { get; set; }
    public DepartmentRow? Department { get; private set; }
    public IReadOnlyList<DepartmentMemberRow> People { get; private set; } = Array.Empty<DepartmentMemberRow>();

    public async Task OnGetAsync(CancellationToken ct)
    {
        ReadRefusal();
        await LoadAsync(ct);
        Rows = RowsOf(People);
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        if (!await ReadyAsync(ct)) return;
        try
        {
            Department = await Repo.GetAsync(Id, ct);
            if (Department is null) { Error = "There is no such department."; return; }
            People = await Repo.MembersAsync(Id, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogError(ex, "department {Id}", Id);
            Error = "The department could not be read: " + ex.Message;
        }
    }

    [SI.Management.Web.Audit.Audited("department.department.save")]
    public async Task<IActionResult> OnPostSaveAsync(string? name, string? mail, string? description, string? matchValues, string? maintenanceWindows, CancellationToken ct)
    {
        var r = await Safely(async () => (await Repo.SaveAsync(new DepartmentInput(Id, name ?? "", mail, description, matchValues, maintenanceWindows), User.ChangeName(), ct)).Result, "The department");
        return Done(r, "/Admin/Departments/Edit", new { id = Id });
    }

    /// <summary>
    /// #335: the PEOPLE TABLE saved in one go -- every row is a person and a role; a row removed (or marked Remove) takes
    /// the person out of that role, a new row adds one. One transaction, one change-log row per change. Refused: the page
    /// again with the reason and the rows as posted.
    /// </summary>
    [SI.Management.Web.Audit.Audited("department.member.set")]
    public async Task<IActionResult> OnPostPeopleAsync(List<PeopleRow>? rows, CancellationToken ct)
    {
        await LoadAsync(ct);
        Rows = rows ?? new();
        if (Department is null) return Page();
        var (members, problems) = await Resolver.ResolveRowsAsync(Id, Rows, People, ct);
        var r = problems.Count > 0
            ? new WriteResult(WriteStatus.Refused, string.Join("; ", problems) + " -- nothing was saved")
            : await Safely(() => Repo.SetPeopleAsync(Id, members, User.ChangeName(), ct), "The people");
        if (r.Status == WriteStatus.Saved) return Done(r, "/Admin/Departments/Edit", new { id = Id });
        Refusal = "The people were not saved: " + r.Message;
        TempData["toast"] = Refusal;
        TempData["toastKind"] = "error";
        if (Rows.Count == 0 || Rows[^1].Person is { Length: > 0 }) Rows.Add(new PeopleRow());
        return Page();
    }

    [SI.Management.Web.Audit.Audited("department.department.retire")]
    public async Task<IActionResult> OnPostRetireAsync(string? reason, CancellationToken ct)
    {
        var r = await Safely(() => Repo.RetireAsync(Id, reason ?? "", User.ChangeName(), ct), "The retirement");
        return r.Status == WriteStatus.Saved ? Done(r, "/Admin/Departments/Index") : Done(r, "/Admin/Departments/Edit", new { id = Id });
    }
}


// ---- the policy: rules, overrides, and "why is this asset there" ----------------------------------------------------

public sealed class RulesModel(DepartmentRepository repo, ISettingsStoreReader settings, ILogger<RulesModel> log) : DepartmentAdminModel(repo, log)
{
    public IReadOnlyList<RuleRow> Rules { get; private set; } = Array.Empty<RuleRow>();
    public IReadOnlyList<OverrideRow> Overrides { get; private set; } = Array.Empty<OverrideRow>();
    public IReadOnlyList<DepartmentRow> Active { get; private set; } = Array.Empty<DepartmentRow>();
    public ResponsibilityPolicy Policy { get; private set; } = ResponsibilityPolicy.Defaults;

    [BindProperty(SupportsGet = true)] public string? Asset { get; set; }
    [BindProperty(SupportsGet = true)] public string? Recommendation { get; set; }
    public ResponsibilityAnswer? Check { get; private set; }
    public string? CheckNote { get; private set; }
    public string? StoredAnswer { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        ReadRefusal();
        if (!await ReadyAsync(ct)) return;
        Rules = await Repo.RulesAsync(ct);
        Overrides = await Repo.OverridesAsync(null, 500, ct);
        Active = await Repo.ListAsync(false, ct);
        Policy = ResponsibilityPolicy.From((await settings.ReadSettingsAsync(ct)).Rows);
        if (!string.IsNullOrWhiteSpace(Asset)) await CheckAsync(ct);
    }

    private async Task CheckAsync(CancellationToken ct)
    {
        string key;
        try { key = ProDataFilters.AssetKey(Asset)!; }
        catch (ArgumentException ex) { CheckNote = ex.Message; return; }
        (string? Name, string? Kind, IReadOnlyList<AssetTagValue> Tags, string? StoredSource, string? StoredDepartment)? facts;
        try { facts = await Repo.AssetFactsAsync(key, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogWarning(ex, "asset facts for the responsibility check");
            CheckNote = "The asset's data could not be read from the Pro database: " + ex.Message + " (run setup\\Initialize-SIDataSql.ps1 again if a table is missing; it only adds).";
            return;
        }
        if (facts is null) { CheckNote = "That asset key is not in the Pro database's CI list."; return; }
        var f = facts.Value;
        var ao = Overrides.FirstOrDefault(o => o.Scope == "asset" && string.Equals(o.AssetKey, key, StringComparison.OrdinalIgnoreCase));
        var rk = string.IsNullOrWhiteSpace(Recommendation) ? null : Recommendation.Trim();
        var ro = rk is null ? null : Overrides.FirstOrDefault(o => o.Scope == "recommendation" && string.Equals(o.RecommendationKey, rk, StringComparison.OrdinalIgnoreCase));
        Check = ResponsibilityResolver.Resolve(
            Active.Select(d => new DepartmentDef(d.DepartmentId, d.Name, d.MatchList)).ToList(),
            Policy.Sources, Policy.TagNames, Policy.DefaultDepartment,
            Rules.Select(r => new ResponsibilityRuleDef(r.RuleId, r.Kind, r.Pattern, r.DepartmentId, r.SortOrder, r.Enabled)).ToList(),
            ro is null ? null : ((int)ro.OverrideId, ro.DepartmentId), ao is null ? null : ((int)ao.OverrideId, ao.DepartmentId),
            f.Name, f.Kind, f.Tags);
        StoredAnswer = f.StoredSource is null ? null : $"{f.StoredDepartment ?? "Unassigned"} ({f.StoredSource})";
        CheckTags = f.Tags;
    }

    public IReadOnlyList<AssetTagValue> CheckTags { get; private set; } = Array.Empty<AssetTagValue>();
    public string NameOf(int? id) => id is { } i ? Active.FirstOrDefault(d => d.DepartmentId == i)?.Name ?? $"department {i}" : "Unassigned";

    [SI.Management.Web.Audit.Audited("responsibility.rule.add")]
    public async Task<IActionResult> OnPostAddRuleAsync(string? kind, string? pattern, int departmentId, int sortOrder, string? note, CancellationToken ct) =>
        Done(await Safely(() => Repo.AddRuleAsync(new RuleInput(kind ?? "", pattern ?? "", departmentId, sortOrder, note), User.ChangeName(), ct), "The rule"), "/Admin/Departments/Rules");

    [SI.Management.Web.Audit.Audited("responsibility.rule.remove")]
    public async Task<IActionResult> OnPostRemoveRuleAsync(int ruleId, CancellationToken ct) =>
        Done(await Safely(() => Repo.RemoveRuleAsync(ruleId, User.ChangeName(), ct), "The removal"), "/Admin/Departments/Rules");

    [SI.Management.Web.Audit.Audited("responsibility.override.set")]
    public async Task<IActionResult> OnPostOverrideAsync(string? scope, string? key, int departmentId, string? reason, CancellationToken ct) =>
        Done(await Safely(() => Repo.OverrideAsync(scope ?? "", string.IsNullOrWhiteSpace(key) ? Array.Empty<string>() : new[] { key.Trim() }, departmentId, reason ?? "", User.ChangeName(), ct), "The override"), "/Admin/Departments/Rules");

    [SI.Management.Web.Audit.Audited("responsibility.override.revoke")]
    public async Task<IActionResult> OnPostRevokeAsync(long overrideId, string? reason, CancellationToken ct) =>
        Done(await Safely(() => Repo.RevokeOverrideAsync(overrideId, reason ?? "", User.ChangeName(), ct), "The revocation"), "/Admin/Departments/Rules");
}

/// <summary>The responsibility settings as the data sync reads them (cfg.Setting, scope 'solution'), with the same defaults.</summary>
public sealed record ResponsibilityPolicy(IReadOnlyList<string> Sources, IReadOnlyList<string> TagNames, string? DefaultDepartment)
{
    public static readonly ResponsibilityPolicy Defaults = new(["tags", "rules"], ["Department", "Owner", "CostCenter"], null);

    public static ResponsibilityPolicy From(IEnumerable<SettingRow> rows)
    {
        var sol = rows.Where(r => r.Scope == "solution").ToDictionary(r => r.Name, r => r.ValueJson, StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<string>? List(string name)
        {
            if (!sol.TryGetValue(name, out var j) || j is null) return null;
            try
            {
                using var d = JsonDocument.Parse(j);
                var items = d.RootElement.ValueKind == JsonValueKind.Array ? d.RootElement.EnumerateArray().Select(e => e.ToString()) : new[] { d.RootElement.ToString() };
                return items.SelectMany(v => v.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList();
            }
            catch (JsonException) { return null; }
        }
        string? Text(string name)
        {
            if (!sol.TryGetValue(name, out var j) || j is null) return null;
            try { using var d = JsonDocument.Parse(j); return d.RootElement.ValueKind == JsonValueKind.String ? d.RootElement.GetString() : null; }
            catch (JsonException) { return null; }
        }
        return new ResponsibilityPolicy(
            List("SI_Pro_Responsibility_Sources")?.Select(s => s.ToLowerInvariant()).Where(s => s is "tags" or "rules").Distinct().ToList() ?? Defaults.Sources,
            List("SI_Pro_Responsibility_TagNames") ?? Defaults.TagNames,
            string.IsNullOrWhiteSpace(Text("SI_Pro_Responsibility_DefaultDepartment")) ? null : Text("SI_Pro_Responsibility_DefaultDepartment")!.Trim());
    }
}
