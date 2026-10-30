using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Advisors;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.GetStarted;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Get Started (Admin) -- a WIZARD, the way ELDK's /Forms/Wizard is built (#446; operator: "show options in the wizard,
/// dont link to things" / "all fields must be in the get started, writing to the same setting. we use forms in eldk"):
/// ONE page, the step by ?step=id, "N of M steps done" + the progress bar + one chip per step, and the step's OWN FORM in
/// its card -- the settings it needs (the Settings page's editor, saved through the same <see cref="SettingsSaver"/>),
/// the people picker for who can manage it, Run now for the collection. Previous / Save &amp; exit / Save &amp; next ->;
/// every save redirects (post / redirect / get); a refused save shows the same step with the reasons under the fields.
/// Done is CHECKED FROM THE DATA on every visit -- there is no tick to set. The menu's red ! asks <see cref="OnGetBadgeAsync"/>.
/// </summary>
public sealed class GetStartedModel : PageModel
{
    private readonly GetStartedService _svc;
    private readonly SettingsCatalog _catalog;
    private readonly ISettingsStoreReader _reader;
    private readonly SettingsSaver _saver;
    private readonly IAccessStore _access;
    private readonly IDirectoryNames _names;
    private readonly IFlowStore _flow;
    private readonly IJobsClient _jobs;
    private readonly MailOverviewLoader _mail;
    private readonly ISignInMailer _mailer;
    private readonly ConnectorRepository _connectors;
    private readonly SI.Management.Web.Audit.IChangeAttributionWriter _attribution;
    private readonly AiKeyStore _aiKeys;
    private readonly IConfiguration _config;
    private readonly Microsoft.Extensions.Options.IOptions<JobsOptions> _jobOptions;
    private readonly ILogger<GetStartedModel> _log;

    public GetStartedModel(GetStartedService svc, SettingsCatalog catalog, ISettingsStoreReader reader, SettingsSaver saver, IAccessStore access,
        IDirectoryNames names, IFlowStore flow, IJobsClient jobs, MailOverviewLoader mail, ISignInMailer mailer, ConnectorRepository connectors,
        SI.Management.Web.Audit.IChangeAttributionWriter attribution, AiKeyStore aiKeys, IConfiguration config, Microsoft.Extensions.Options.IOptions<JobsOptions> jobOptions, ILogger<GetStartedModel> log)
    {
        _svc = svc; _catalog = catalog; _reader = reader; _saver = saver; _access = access; _names = names; _flow = flow; _jobs = jobs; _mail = mail; _mailer = mailer;
        _connectors = connectors; _attribution = attribution; _aiKeys = aiKeys; _config = config; _jobOptions = jobOptions; _log = log;
    }

    [BindProperty(SupportsGet = true)] public string? Step { get; set; }

    public GetStartedResult Result { get; private set; } = null!;
    public int Index { get; private set; }
    public StepState Current => Result.Steps[Index];
    public StepState? Previous => Index > 0 ? Result.Steps[Index - 1] : null;
    public StepState? Next => Index < Result.Steps.Count - 1 ? Result.Steps[Index + 1] : null;
    public bool CanSuperAdmin => User.IsSuperAdmin();

    /// The current step's settings, in the step's order, with what is stored now.
    public IReadOnlyList<SettingField> Fields { get; private set; } = Array.Empty<SettingField>();
    /// The step's Advanced details, folded away (the AI step: the Key Vault secret NAME of the key -- the paste box is the
    /// one key field).
    public IReadOnlyList<SettingField> AdvancedFields { get; private set; } = Array.Empty<SettingField>();
    /// The AI step: the key's state beside the paste box -- stored / waiting for the updater / the updater's reason --
    /// read from cfg.PendingSecret and the setting on EVERY load, so a failure stays until it is stored or replaced.
    public SecretStateView? AiKeyState { get; private set; }
    /// The AI step: a pasted text that is not a key (nothing was stored), shown under the paste box.
    public string? AiKeyError { get; private set; }
    /// The AI step: the switch's saved value, so the status line can say "not saved yet" the moment the box is ticked.
    public bool AiSavedOn { get; private set; }
    /// #503: the mail step's shared mailbox, in two steps (Pages/Shared/_MailboxSteps.cshtml).
    public SharedMailboxSteps? MailboxSteps { get; private set; }
    /// A refused save: why, per setting, and in a sentence.
    public IReadOnlyDictionary<string, string> Errors { get; private set; } = new Dictionary<string, string>();
    public string? Problem { get; private set; }
    /// The access step: who has a role through this page today, and whether names can be searched.
    public IReadOnlyList<AccessAssignment> Managers { get; private set; } = Array.Empty<AccessAssignment>();
    public bool NameLookup => _names.Enabled;
    /// The mail step: the address the test mail goes to (the signed-in person).
    public string? TestTo => User.FindFirst("preferred_username")?.Value ?? User.Identity?.Name;
    /// The connectors step: the connectors (cfg.Connector, read fresh), the form's values (what is set up now, or what a
    /// refused save posted), and whether the database has the connector table at all.
    public IReadOnlyList<ConnectorRow> ConnectorRows { get; private set; } = Array.Empty<ConnectorRow>();
    /// Per card (<see cref="GetStartedConnector.Slots"/>): what is set up now, or what a refused save posted.
    public IReadOnlyDictionary<string, GetStartedConnector.Form>? ConnectorForms { get; private set; }
    public bool ConnectorTableMissing { get; private set; }

    /// The permissions step: this install's names for the prefilled fix commands (settings + the Jobs section).
    public PermissionFixInstall PermissionInstall => GetStartedPermissionFix.Resolve(Result.Facts?.Settings, _jobOptions.Value);

    public static string Href(string id) => "/Admin/GetStarted?step=" + Uri.EscapeDataString(id);

    public async Task OnGetAsync(CancellationToken ct)
    {
        // every visit checks again -- the page never shows a remembered state
        Result = await _svc.EvaluateAsync(fresh: true, ct);
        Index = Result.IndexOf(Step);
        await LoadFormAsync(ct);
    }

    private async Task LoadFormAsync(CancellationToken ct)
    {
        var step = Current.Step;
        if (step.Form == "settings" && step.Fields is { Count: > 0 } names)
        {
            try
            {
                var (rows, _) = await _reader.ReadSettingsAsync(ct);
                var all = rows.ToLookup(r => r.Name, StringComparer.OrdinalIgnoreCase);
                Fields = names.Select(n => _catalog.Find(n)).Where(s => s is not null)
                    // each field gets ITS OWN stored rows (as the Settings page passes them) -- given every row, a field showed
                    // the value of whichever setting was stored first, and every other setting's scope as "also set for"
                    .Select(s => SettingsLayout.Field(s!, all[s!.Name].ToList(), _catalog, all)).ToList();
                if (Current.Id == "ai")
                {
                    // ONE key field: the paste box with the stored state beside it; the secret's NAME is an Advanced detail
                    AdvancedFields = Fields.Where(f => f.Setting.Name == AiKeyStore.KeySetting).ToList();
                    Fields = Fields.Where(f => f.Setting.Name != AiKeyStore.KeySetting).ToList();
                    AiSavedOn = string.Equals(MailMode.Plain(MailMode.RowOf(rows, GetStartedGuide.AiSwitch)?.ValueJson)?.Trim(), "true", StringComparison.OrdinalIgnoreCase);
                    AiKeyState = await _aiKeys.StateAsync(rows, ct);
                }
                // #503: the mail step names the shared mailbox in two steps (the address is typed only there)
                if (Current.Id == "mail") MailboxSteps = SI.Management.Web.Pages.Admin.Settings.EmailModel.StepsOf(rows, User, _config, _jobOptions.Value);
                // #633 (owner 2026-10-13): with an SMTP relay the sender is ONE field ("Mail sender address"); the older sender
                // setting is shown only while it holds a value (it is then used instead of the field above it)
                if (Current.Id == "mail") Fields = Fields.Where(f => !GetStartedGuide.MailFieldOnlyWhenSet(f.Setting.Name) || !string.IsNullOrWhiteSpace(f.Text)).ToList();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "the settings of a Get Started step could not be read");
                Problem = "The settings could not be read from the Pro database: " + ex.Message;
            }
        }
        if (step.Form == "access")
        {
            try { Managers = (await _access.TableExistsAsync(ct)) ? (await _access.ListAsync(ct)).Where(a => a.Role is SiRole.Admin or SiRole.SuperAdmin).ToList() : Array.Empty<AccessAssignment>(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the access assignments could not be read"); }
        }
        if (step.Form == "connectors")
        {
            try
            {
                ConnectorTableMissing = !await _connectors.TableExistsAsync(ct);
                ConnectorRows = ConnectorTableMissing ? Array.Empty<ConnectorRow>() : await _connectors.ListAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "the connectors could not be read");
                Problem ??= "The connectors could not be read from the Pro database: " + ex.Message;
            }
            ConnectorForms ??= GetStartedConnector.PrefillAll(ConnectorRows);
        }
    }

    /// #633: the label a field carries in this step (null = the catalog's) -- the mail step names each field for what it is
    /// with the way of sending it belongs to.
    public string? FieldLabel(SettingField f) => Current.Id == "mail" ? GetStartedGuide.MailFieldLabel(f.Setting.Name) : null;

    /// The show-when rule of a field in this step ("SI_Mail_Mode=smtp"), and whether it starts hidden.
    public (string? Rule, bool Hidden) ShowWhen(SettingField f)
    {
        if (Current.Id != "mail" || GetStartedGuide.MailFieldMode(f.Setting.Name) is not { } mode) return (null, false);
        var chosen = Fields.FirstOrDefault(x => x.Setting.Name == "SI_Mail_Mode")?.Text;
        return ("SI_Mail_Mode=" + mode, !string.IsNullOrEmpty(chosen) && !string.Equals(chosen, mode, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// One post for every step: __step (the step), __dir (prev | stay | next | exit) and __action (run | testmail | runconnector). The
    /// step's form is saved first -- prev saves nothing -- then the wizard moves on.
    /// </summary>
    [SI.Management.Web.Audit.Audited("getstarted.step.save")]
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var form = Request.Form;
        Step = form["__step"].ToString();
        var dir = form["__dir"].ToString();
        var action = form["__action"].ToString();
        Result = await _svc.EvaluateAsync(fresh: true, ct);
        // the free version (owner 2026-10-18): a paid step is not a step of this install -- posting it is refused, server side,
        // never quietly mapped to another step
        if (GetStartedGuide.Steps.FirstOrDefault(s => s.Id.Equals(Step, StringComparison.OrdinalIgnoreCase)) is { } paidStep && GetStartedGuide.IsProStep(paidStep) && Result.Steps.All(x => x.Step.Id != paidStep.Id))
            return SI.Management.Web.Licensing.ProFeaturePageFilter.Refuse(Request, SI.Management.Web.Licensing.ProFeatures.ForPage(paidStep.Href.Split('?', '#')[0]) ?? SI.Management.Web.Licensing.ProFeatures.Licence);
        Index = Result.IndexOf(Step);
        var step = Current.Step;
        if (dir == "prev") return Redirect(Href(Previous?.Id ?? step.Id));

        string? saved = null;
        if (step.Form == "settings" && step.Fields is { Count: > 0 } names)
        {
            var r = await _saver.SaveAsync(form, names, User, "/Admin/GetStarted?step=" + step.Id, ct);
            if (!r.Ok) { Errors = r.Errors; Problem = r.Message; await LoadFormAsync(ct); return Page(); }
            if (r.Saved > 0) saved = r.Message;
            // the AI step: the key pasted once is HANDED TO THE UPDATER encrypted (the web app writes no secret and holds no
            // Key Vault right); the updater stores it and points OpenAI_apiKey at the secret's name. Its state is shown
            // beside the paste box on every load -- never as a one-off message that is gone on the next visit.
            if (step.Id == "ai" && form[AiKeyStore.FormField].ToString() is { Length: > 0 } key)
            {
                var keySetting = _catalog.Find(AiKeyStore.KeySetting);
                if (keySetting is not null && keySetting.NeedsSuperAdmin && !User.IsSuperAdmin()) { AiKeyError = "Only a SuperAdmin can store the key."; await LoadFormAsync(ct); return Page(); }
                if (SI.Management.Web.Audit.AuditScope.Current is { } audit) { audit.Target = "/Admin/GetStarted?step=ai, secret=" + AiKeyStore.SecretName; audit.Reason = "Azure OpenAI key handed to the updater (encrypted; the value is never recorded)"; }
                var h = await _aiKeys.StoreAsync(key, User.ChangeName(), ct);
                if (!h.Ok && h.Message == AiKeyStore.NotAKeyText) { AiKeyError = h.Message; await LoadFormAsync(ct); return Page(); }
                saved = (saved is null ? "" : saved + " ") + h.Message;
                if (!h.Ok) { TempData["toast"] = saved; TempData["toastKind"] = "warn"; _svc.Forget(); return Redirect(Href(step.Id)); }
            }
        }
        else if (step.Form == "access" && !string.IsNullOrWhiteSpace(form["PrincipalId"]))
        {
            var (ok, msg) = await SaveManagerAsync(form, ct);
            if (!ok) { Problem = msg; await LoadFormAsync(ct); return Page(); }
            saved = msg;
        }
        else if (step.Form == "connectors")
        {
            var posted = GetStartedConnector.ReadAll(form);
            var (ok, msg) = await SaveConnectorsAsync(posted, form, ct);
            if (!ok) { Problem = msg; ConnectorForms = posted; await LoadFormAsync(ct); return Page(); }
            saved = msg;
            if (action.StartsWith(GetStartedConnector.RunAction, StringComparison.Ordinal))
            {
                var slot = GetStartedConnector.SlotOf(action[GetStartedConnector.RunAction.Length..]);
                saved = (saved is null ? "" : saved + " ") + (slot is null ? "Nothing was started: that connector is not one this step sets up." : await RunConnectorAsync(slot, ct));
                dir = "stay";
            }
        }

        if (action == "run")
        {
            saved = await QueueCollectionAsync(ct);
            dir = "stay";
        }
        else if (action == "testmail")
        {
            saved = (saved is null ? "" : saved + " ") + await QueueTestMailAsync(form["TestTo"].ToString(), ct);
            dir = "stay";
        }

        if (saved is not null) { TempData["toast"] = saved; TempData["toastKind"] = "ok"; }
        _svc.Forget();
        return dir switch
        {
            "exit" => Redirect("/"),
            "stay" => Redirect(Href(step.Id)),
            _ => Redirect(Next is { } n ? Href(n.Id) : Href(step.Id) + "&finished=1"),
        };
    }

    /// The access step: one person or group gets Admin or SuperAdmin -- the same assignment Admin &gt; Access writes.
    private async Task<(bool Ok, string Message)> SaveManagerAsync(IFormCollection form, CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return (false, "Only a SuperAdmin can give someone a role.");
        var id = form["PrincipalId"].ToString().Trim().ToLowerInvariant();
        if (!SqlAccessStore.ObjectId().IsMatch(id)) return (false, "Choose a person or group from the list (or paste an Entra object id).");
        if (AccessClaims.ObjectId(User) is { } me && string.Equals(me, id, StringComparison.OrdinalIgnoreCase)) return (false, "You already manage SecurityInsight -- add someone else.");
        var role = AccessClaims.ParseRole(form["Role"].ToString()) is SiRole r && r is SiRole.Admin or SiRole.SuperAdmin ? r : SiRole.Admin;
        var type = string.Equals(form["PrincipalType"], AccessAssignment.Group, StringComparison.OrdinalIgnoreCase) ? AccessAssignment.Group : AccessAssignment.User;
        var name = form["DisplayName"].ToString().Trim();
        if (name.Length == 0 && _names.Enabled && await _names.NameOfAsync(id, ct) is { } found) { name = found.Name; type = found.Type; }
        if (name.Length == 0) return (false, "Give the person or group a name.");
        var w = await _access.WriteAsync(new AccessAssignment(id, type, name, role, new AccessScope()), null, User.ChangeName(), "Get Started: who can manage SecurityInsight", ct);
        return w.Status == WriteStatus.Saved ? (true, $"{name} can now manage SecurityInsight ({AccessClaims.Label(role)}).") : (false, "Not saved: " + w.Message);
    }

    /// The collection steps' Run now: the whole pipeline, as a request in the install's queue (the Jobs page's Run now).
    private async Task<string> QueueCollectionAsync(CancellationToken ct)
    {
        try { return await QueueAsync("pipeline", "", "A full collection", ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "Run now from Get Started failed");
            return "The collection could not be started: " + ex.Message;
        }
    }

    /// A request in the install's run queue and the runner started to take it -- the Jobs page's Run now (QueueRun).
    private async Task<string> QueueAsync(string scope, string target, string what, CancellationToken ct)
    {
        var (id, outcome) = await _flow.EnqueueAsync(scope, target, User.ChangeName(), ct);
        if (outcome == "Missing")
        {
            // an older Pro database (no queue yet): the runner is started with the request itself
            var env = new Dictionary<string, string> { ["SI_FLOW_TRIGGER"] = "manual" };
            if (scope == "step") env["SI_FLOW_STEP"] = target; else env["SI_FLOW_FORCE"] = "1";
            await _jobs.StartWithEnvAsync(JobFlow.FlowJob, env, ct);
            return what + " starts now.";
        }
        await _jobs.StartWithEnvAsync(JobFlow.FlowJob, new Dictionary<string, string> { ["SI_FLOW_DRAIN"] = "1", ["SI_FLOW_TRIGGER"] = "manual" }, ct);
        return outcome == "Deduplicated" ? what + " is already waiting to start." : $"{what} is queued (request {id}) and starts as soon as nothing else runs.";
    }

    /// <summary>
    /// The connectors step's save: the step's fields as the SAME connector write the Connector setup page stages --
    /// <see cref="ConnectorRepository.Validate"/> first (a refused write writes nothing), then
    /// <see cref="ConnectorRepository.WriteAsync"/> (cfg.Connector + its cfg.ChangeLog row + the version check), then who
    /// changed it (cfg.ChangeAttribution, as Review &amp; commit records it) and the request's audit row with before / after.
    /// Nothing chosen = nothing written; values that change nothing = nothing written.
    /// </summary>
    private async Task<(bool Ok, string? Message)> SaveConnectorsAsync(IReadOnlyDictionary<string, GetStartedConnector.Form> posted, IFormCollection form, CancellationToken ct)
    {
        if (GetStartedConnector.Slots.All(s => GetStartedConnector.IsEmpty(posted[s.Key])) && !await _connectors.TableExistsAsync(ct)) return (true, null);
        if (!await _connectors.TableExistsAsync(ct)) return (false, "Nothing was saved: " + ConnectorRepository.MissingTableMessage);
        var rows = await _connectors.ListAsync(ct);
        // every card's write is built and checked FIRST -- one card refused = nothing is written for any card
        var writes = new List<(ConnectorWrite W, ConnectorRow? Current)>();
        foreach (var s in GetStartedConnector.Slots)
        {
            var f = posted[s.Key];
            var current = GetStartedConnector.Match(rows, s.Kind, s.Direction);
            if (GetStartedConnector.IsEmpty(f) && current is null) continue;
            long? expected = current is not null && long.TryParse(form[GetStartedConnector.VersionPrefix + current.Name], System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : null;
            var w = GetStartedConnector.Build(f, current, expected);
            if (GetStartedConnector.Unchanged(w, current)) continue;
            writes.Add((w, current));
        }
        if (writes.Count == 0) return (true, null);

        var audit = SI.Management.Web.Audit.AuditScope.Current;
        if (audit is not null)
        {
            audit.Target = "/Admin/GetStarted?step=connectors, connector=" + string.Join(",", writes.Select(x => x.W.Name));
            audit.Reason = writes[0].W.Reason;
            audit.BeforeJson = "[" + string.Join(",", writes.Select(x => x.Current is null ? "null" : ConnectorRepository.DefinitionJson(ConnectorRepository.FromRow(x.Current, "Set", null)))) + "]";
            audit.AfterJson = "[" + string.Join(",", writes.Select(x => ConnectorRepository.DefinitionJson(x.W))) + "]";
        }
        var why = writes.SelectMany(x => ConnectorRepository.Validate(x.W).Select(r => GetStartedConnector.TitleOf(x.W.Kind, x.W.Direction, x.W.Name) + ": " + r)).ToList();
        if (why.Count > 0)
        {
            var text = "Nothing was saved: " + string.Join("; ", why);
            audit?.Refused(text);
            return (false, text);
        }
        var by = User.ChangeName();
        var done = new List<string>();
        foreach (var (w, _) in writes)
        {
            var r = await _connectors.WriteAsync(w, by, ct);
            if (r.Status != WriteStatus.Saved)
            {
                var text = (done.Count > 0 ? "Saved: " + string.Join(", ", done) + ". " : "") + (r.Status == WriteStatus.Stale
                    ? $"Not saved: the connector {w.Name} was changed by someone else since this step was opened -- check the values and save again."
                    : $"Not saved: {w.Name}: " + r.Message);
                audit?.Refused(text);
                return (false, text);
            }
            var (change, _) = ChangeService.NewConnector(w);
            if (change is not null)
                await _attribution.RecordAsync(SI.Management.Web.Audit.ChangeAttribution.CorrelationId(), [ChangeService.AttributionOf(change, by)], ct);
            done.Add($"{w.Name} ({(w.Enabled ? "switched on" : "switched off")}, {(w.Mode == "apply" ? "sends" : "whatif: plans and logs, sends nothing")})");
        }
        return (true, (done.Count == 1 ? "The connector " : "The connectors ") + string.Join("; ", done) + (done.Count == 1 ? " is saved." : " are saved.") + " It applies from its next run.");
    }

    /// "Save and run once" of one card: the connector's job now -- the Jobs page's Run now on that job (a step of the
    /// pipeline goes through the run queue, never beside a run that is going; any other job starts at once).
    private async Task<string> RunConnectorAsync(GetStartedConnector.Slot slot, CancellationToken ct)
    {
        var key = GetStartedConnector.JobKey(slot.Kind, slot.Direction);
        var job = "caj-si-" + key;
        var label = JobSchedule.Label(job);
        try
        {
            if (!_jobs.IsConfigured) return "Nothing was started: " + NotConfiguredJobsClient.Why;
            var jobs = await _jobs.ListAsync(ct);
            if (!jobs.Any(j => j.Name == job)) return $"Nothing was started: this install has no {label} job ({job}) yet -- run setup once to add it.";
            var stored = await _flow.ReadAsync(ct);
            var mode = stored.Mode is "flow" or "schedules" ? stored.Mode : JobFlow.InferMode(jobs);
            var inFlow = stored.Definition is { } d ? d.Steps.Any(s => s.Job == key) : JobFlow.DefaultOrder.Contains(key);
            if (mode == "flow" && inFlow && jobs.Any(j => j.Name == JobFlow.FlowJob))
                return await QueueAsync("step", key, label, ct) + " This step turns done when its run has finished well.";
            var exec = await _jobs.StartAsync(job, ct);
            return $"{label} starts now (execution {exec}). This step turns done when its run has finished well.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "Run once from Get Started failed");
            return $"{label} could not be started: " + ex.Message;
        }
    }

    /// The mail step's test mail -- queued in the outbox; the mail job sends it through the transport just saved.
    private async Task<string> QueueTestMailAsync(string to, CancellationToken ct)
    {
        to = string.IsNullOrWhiteSpace(to) ? TestTo ?? "" : to.Trim();
        if (!SettingsForm.IsMailAddress(to)) return $"No test mail: '{to}' is not an e-mail address.";
        try
        {
            var o = await _mail.LoadAsync(ct);
            if (o.Mode.IsNone) return "No test mail: mail is off.";
            await _mailer.SendAsync(MailTestMail.Build(to, o.Mode, o.From), User.ChangeName(), ct);
            return $"A test mail to {to} is queued -- it is sent within minutes; this step turns done when it went out.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the test mail could not be queued");
            return "The test mail could not be queued: " + ex.Message;
        }
    }

    /// The menu's red !: how many required steps are open (from the cached evaluation, at most a minute old).
    public async Task<IActionResult> OnGetBadgeAsync(CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        var r = await _svc.EvaluateAsync(fresh: false, ct);
        return new JsonResult(new { openRequired = r.OpenRequired, done = r.Done, total = r.Total });
    }
}
