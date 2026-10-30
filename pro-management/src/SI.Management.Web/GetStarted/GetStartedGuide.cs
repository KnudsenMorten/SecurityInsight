using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Pages.Admin;
using SI.Management.Web.Settings;

namespace SI.Management.Web.GetStarted;

/// <summary>
/// What Get Started reads, once per visit (<see cref="GetStartedFactsReader"/>): the state each step's check is computed
/// from. Nothing here is a "done" flag -- every value is the install's own data (the licence the updater verified, the
/// role assignments, the mail transport's recorded status, the engines' run records, the loaded collections, the tiers,
/// the ring, the CMDB, the connectors, the held close sets, the settings). <see cref="Unread"/> names the facts that could
/// not be read: a step built on one says so, and counts as open (never guessed done).
/// </summary>
public sealed record GetStartedFacts
{
    public DateTime NowUtc { get; init; } = DateTime.UtcNow;
    /// The installed licence as the updater last verified it (null = nothing recorded yet).
    public InstalledLicence? Licence { get; init; }
    /// Role assignments made on Access (roles + scopes).
    public IReadOnlyList<AccessAssignment> Access { get; init; } = Array.Empty<AccessAssignment>();
    /// The mail transport: the mode, the recorded restriction and the last test mail (null = not read).
    public MailOverview? Mail { get; init; }
    /// The newest run of each engine in the last <see cref="GetStartedGuide.RunDays"/> days (Run health's own grouping).
    public IReadOnlyList<LatestRun> LatestRuns { get; init; } = Array.Empty<LatestRun>();
    /// Each engine's newest permission self-check in the same window (the run-health END records' PermissionGaps,
    /// <see cref="GetStartedPermissions.Latest"/>); read with the runs, so "runs" unread covers it too.
    public IReadOnlyList<EnginePermissions> Permissions { get; init; } = Array.Empty<EnginePermissions>();
    /// Complete Risk Analysis Detailed collections loaded into the web app's database, and the newest one's time.
    public int CompleteCollections { get; init; }
    public DateTime? NewestCollectionUtc { get; init; }
    /// Assets per tier ("0".."3", "Unclassified").
    public IReadOnlyDictionary<string, long> AssetsPerTier { get; init; } = new Dictionary<string, long>();
    /// The update ring as it was recorded for the install (null = none recorded), and the SI_UpdateRing setting.
    public InstallRing? Ring { get; init; }
    public int? RingSetting { get; init; }
    /// CMDB services of the authoritative source (not retired), and how many of them have at least one asset.
    public int Services { get; init; }
    public int ServicesWithMembers { get; init; }
    /// The connectors (cfg.Connector) and their newest runs.
    public IReadOnlyList<ConnectorRow> Connectors { get; init; } = Array.Empty<ConnectorRow>();
    public IReadOnlyList<ConnectorRunRow> ConnectorRuns { get; init; } = Array.Empty<ConnectorRunRow>();
    /// Close sets a safety check holds that are still waiting for a decision (held, not expired).
    public int OpenHolds { get; init; }
    /// #446: who holds a role on the web app's enterprise application in Entra (the installer, the named administrators);
    /// null = not known (the directory lookup is off or could not read it).
    public IReadOnlyList<SI.Management.Web.Auth.AppRoleHolder>? EntraRoles { get; init; }
    /// When this install's Pro database was created -- the install's age (null = not known). "No run in the last 7 days"
    /// is never said on an install younger than that.
    public DateTime? InstalledUtc { get; init; }
    /// A pipeline run that is in progress now, and when it started (null = none is running).
    public DateTime? RunStartedUtc { get; init; }
    /// The settings rows (cfg.Setting) -- for the Azure OpenAI connection.
    public IReadOnlyList<SettingRow> Settings { get; init; } = Array.Empty<SettingRow>();
    /// The facts that could not be read (keys of <see cref="GetStartedGuide"/>: "licence", "access", ...).
    public IReadOnlySet<string> Unread { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public bool Read(string key) => !Unread.Contains(key);
}

/// <summary>One step of Get Started: what it is, whether it is required, the page that does the work, and its check.
/// <see cref="Checkable"/> false = the web app cannot see it (shown, linked, never counted and never marked done).
/// <see cref="Href"/> starting with "https://" opens outside SecurityInsight.
/// THREE GROUPS (owner 2026-10-12, "Required / Waiting / Optional": "many steps cannot be completed in a raw/firsttime
/// install ... maybe we need to make them optional"): <see cref="Required"/> = a person must do it (red while open; the
/// only steps counted in "N of M steps done" and in the menu's red dot); <see cref="Waits"/> = it closes by itself when
/// the first run's data is there (a neutral colour, never red, never counted); neither = optional (grey, never counted).</summary>
/// #446 (operator: "show options in the wizard, dont link to things" / "all fields must be in the get started, writing to
/// the same setting. we use forms in eldk"): every step is a FORM in the step itself. <see cref="Form"/> says which:
/// "settings" = the catalog settings in <see cref="Fields"/>, edited with the Settings page's own editor and saved through
/// the same save (SettingsSaver); "access" = who can manage SecurityInsight (the people picker + a role); "run" = the
/// collection's state and Run now; "tiers" = the assets per tier; "connectors" = ServiceNow or the SQL CMDB with its
/// connection fields, on / off and Run once (<see cref="GetStartedConnector"/>, the same connector store as Connector setup).<see cref="Href"/> / <see cref="Action"/> remain for the
/// deep link a mail or the menu badge points at -- the step never needs them to be done.
public sealed record GetStartedStep(string Id, string Title, bool Required, string What, string Href, string Action,
    Func<GetStartedFacts, StepCheck> Check, bool Checkable = true, string? Need = null, string Form = "settings", IReadOnlyList<string>? Fields = null,
    bool Waits = false)
{
    public bool External => Href.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
}

/// The result of one check: done or not, and the current state in a few words ("0 recipients", "valid until 2027-01-31").
/// <see cref="Waiting"/> = not done, and nothing for a person to do: it closes by itself (the first run, the licence
/// being checked) -- neutral, never red, whatever the step's group. <see cref="Problem"/> = something is wrong that a
/// person must look at (a mail setup whose test failed) -- red even on a step that is not required, still never counted.
/// <see cref="Chosen"/> = not set up by choice ("No mail"): a finished choice, said without "not done yet".
public sealed record StepCheck(bool Done, string Note, bool Waiting = false, bool Problem = false, bool Chosen = false);

/// One step as it stands now.
public sealed record StepState(GetStartedStep Step, bool Done, string Note, bool Waiting = false, bool Problem = false, bool Chosen = false)
{
    public string Id => Step.Id;
    public bool Required => Step.Required;
    /// The pill: "done" (green check), "open" (red !: a required step a person must do, or a problem), "waiting"
    /// (neutral: it closes by itself, or a step of the waiting group that is not done), "optional" (grey).
    public string Kind => Done ? "done" : Waiting ? "waiting" : Problem || Required ? "open" : Step.Waits ? "waiting" : "optional";
    /// A required step a person must do now -- what the menu's red dot, the daily reminder and the report count.
    public bool OpenRequired => Required && Kind == "open";
    /// The words before the note ("Not done yet -- 1 person with Admin"); empty when the note says it all ("Waiting for
    /// the first run ...").
    public string Label => Kind switch
    {
        "done" => "Done",
        "open" => "Not done yet",
        "waiting" => Waiting ? "" : "Not done yet",
        _ => Chosen ? "Optional" : "Optional -- not done yet",
    };
}

/// The whole guide as it stands now.
public sealed record GetStartedResult(IReadOnlyList<StepState> Steps)
{
    /// The facts the steps were checked from (a step's form shows them: the assets per tier, the connectors, ...).
    public GetStartedFacts? Facts { get; init; }

    /// The REQUIRED steps -- the only ones "N of M steps done" counts (a step that waits for the first run, and an
    /// optional one, is never counted).
    public int Total => Steps.Count(s => s.Required);
    public int Done => Steps.Count(s => s.Required && s.Done);
    public int Percent => Total == 0 ? 100 : (int)Math.Round(100.0 * Done / Total);
    /// Required steps a person must do now: the red ! on the menu while this is above 0. A required step that only
    /// waits (the licence being checked) is not one of them.
    public int OpenRequired => Steps.Count(s => s.OpenRequired);
    public bool Ready => OpenRequired == 0;

    /// The step a bare visit opens: the first required step a person must do; when there is none, the first step that
    /// is not done (waiting or optional); else the first step.
    public string DefaultStepId =>
        (Steps.FirstOrDefault(s => s.OpenRequired)
         ?? Steps.FirstOrDefault(s => !s.Done && s.Step.Checkable)
         ?? Steps[0]).Id;

    /// The index of a step by id (case-insensitive); an unknown or empty id opens the default step.
    public int IndexOf(string? id)
    {
        var i = string.IsNullOrWhiteSpace(id) ? -1 : Steps.ToList().FindIndex(s => s.Id.Equals(id.Trim(), StringComparison.OrdinalIgnoreCase));
        return i >= 0 ? i : Steps.ToList().FindIndex(s => s.Id == DefaultStepId);
    }
}

/// <summary>
/// GET STARTED (operator 2026-10-07: "I want to have an Get Started in the menu, similar to how i have made it in ELDK ...
/// it should show the incompleted steps"). The ordered steps that take a new SecurityInsight Pro install to a working one,
/// each CHECKED FROM THE DATA on every visit -- never a manual tick, never a stored "done" flag. Each step explains itself in
/// plain words and links to the page that does the work: Get Started guides, it never duplicates a page.
/// Pure: <see cref="Evaluate"/> turns facts into the guide's state.
/// </summary>
public static class GetStartedGuide
{
    /// The engines whose newest run must have succeeded for "Data sources" -- the four profiling engines.
    public static readonly IReadOnlyList<string> SourceEngines = ["identity", "azure", "endpoint", "publicip"];
    /// How far back the run records are read.
    public const int RunDays = 7;
    /// "Web app access": at least this many people with Admin or SuperAdmin (a group with that role counts as enough).
    public const int MinAdmins = 2;

    /// The mail step's fields: the choice (shared mailbox / SMTP relay / no mail), the shared mailbox, and the SMTP relay's
    /// own fields -- shown only while SMTP is chosen (data-show-when).
    /// #633: SI_Mail_From sits right under "Mail sender address" (SMTPFrom): with SMTP it is used instead of it.
    public static readonly IReadOnlyList<string> MailFields =
        ["SI_Mail_Mode", "SI_Mail_ProbeMailbox", "SmtpServer", "SMTPPort", "SMTP_UseSSL", "SMTPFrom", "SI_Mail_From", "Mail_SendAnonymous", "SMTPUser", "SMTPPassword"];

    /// #633 (owner 2026-10-13: "this is also confusing ... it mentions shared mailbox"): with an SMTP relay the step says
    /// nothing about a shared mailbox -- SI_Mail_From (the shared mailbox's address, which with SMTP is the From address and
    /// wins over "Mail sender address") is shown only while it holds a value, and labelled for what it does there.
    public static bool MailFieldOnlyWhenSet(string name) => name == "SI_Mail_From";

    /// #633: the mail step's own label of a field (null = the catalog's).
    public static string? MailFieldLabel(string name) => name switch
    {
        "SI_Mail_From" => "Sender address (used instead of the one above)",
        "SI_Mail_ProbeMailbox" => "Mailbox to prove the restriction (its e-mail address)",
        _ => null,
    };

    /// Which mail mode a mail field belongs to (null = every mode): the SMTP relay's fields only with smtp.
    public static string? MailFieldMode(string name) => name is "SmtpServer" or "SMTPPort" or "SMTP_UseSSL" or "SMTPFrom" or "Mail_SendAnonymous" or "SMTPUser" or "SMTPPassword" ? "smtp"
        // #503: with a shared mailbox the address is typed only in the two mailbox steps; SI_Mail_From stays the SMTP From
        : name is "SI_Mail_ProbeMailbox" ? "sharedMailbox" : name is "SI_Mail_From" ? "smtp" : null;

    private static bool IsTrue(IReadOnlyList<SI.Management.Web.Settings.SettingRow> rows, string name) =>
        rows.Any(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && (r.ValueJson ?? "").Trim().Equals("true", StringComparison.OrdinalIgnoreCase));

    public static readonly IReadOnlyList<GetStartedStep> Steps = new GetStartedStep[]
    {
        // ---- required: a person does these; the only steps counted and the only ones that are red ---------------------
        new("licence", "Licence", true,
            "SecurityInsight Pro runs on a licence from Invardia. The nightly updater checks the installed licence; while it is missing, invalid or expired the Pro jobs do not run.",
            "/Admin/Settings#licence-request", "Open the licence", Licence, Fields: ["SI_LicenseRequest_Auto", "SI_LicenseRequest_ContactEmail"]),
        new("access", "Who can manage SecurityInsight", true,
            "Give at least two people -- or one group -- the Admin or SuperAdmin role, so more people than the one who installed SecurityInsight can manage it.",
            "/Admin/Access", "Open Access (roles + scopes)", Access, Need: "superadmin", Form: "access"),
        new("ring", "Update ring", true,
            "The update ring decides when this install receives new versions (ring 0 first, ring 3 last). It is set at installation and can be changed in Settings.",
            "/Admin/Settings?q=SI_UpdateRing", "Open Settings", Ring, Fields: ["SI_UpdateRing"]),
        // ---- waiting: these close by themselves when the first run's data is there -- neutral, never red, never counted --
        new("sources", "Data sources", false,
            "SecurityInsight reads Entra ID (identity), Azure, Defender for Endpoint and your public IP addresses with its own identity. Each one needs its read permissions; the newest run of every source must have succeeded.",
            "/Admin/RunHealth", "Open Run health", Sources, Form: "run", Waits: true),
        new("permissions", "Permissions", false,
            "Every SecurityInsight engine checks its own permissions when it runs -- its application permissions, its Azure role and, on SecurityInsight Pro, its access to the database -- and records what is missing. This step is done when the newest run of every engine reports nothing missing; each gap says how to fix it.",
            "/Admin/RunHealth", "Open Run health", GetStartedPermissions.Check, Form: "permissions", Waits: true),
        new("collection", "First full collection", false,
            "One complete run: every source collected, the Risk Analysis built and its detailed results loaded into SecurityInsight. The dashboards and views show nothing before it.",
            "/Admin/Jobs", "Open Jobs", Collection, Form: "run", Waits: true),
        new("tiers", "Tiers", false,
            "Every asset gets a tier (0 = the most critical). Look at the tier board: are your most critical assets (domain controllers, identity systems, key servers) in tier 0?",
            "/Tiers", "Open the tier board", Tiers, Form: "tiers", Waits: true),
        // ---- optional: grey, never counted ------------------------------------------------------------------------------
        // "No mail" is a finished choice; a mail setup whose test failed is still shown as a problem
        new("mail", "Mail", false,
            "SecurityInsight sends its reports, safety-check alerts and close-loop mails through one mail setup: an Office 365 shared mailbox (recommended) or your own SMTP relay. Set it up and send a test mail -- or leave it at No mail.",
            "/Admin/Settings/Email#mail", "Set up mail", Mail, Fields: MailFields),
        new("cmdb", "CMDB services", false,
            "Group assets into the services they run (from your CMDB or created here), so risk can be read per service and per owner.",
            "/Cmdb", "Open the CMDB", Cmdb, Fields: ["SI_EnableCmdbProvider", "SI_Pro_CmdbSql_Enabled", "SI_Pro_CmdbSql_Kinds"]),
        new("connectors", "Connectors", false,
            "Where SecurityInsight sends what it finds: the SQL vulnerability target (on by default in Pro), the SQL CMDB hand-off, ServiceNow vulnerabilities and the ServiceNow CMDB -- each its own connector, any of them on at once. Switch on the ones you use and let each run once.",
            "/Admin/ConnectorSetup", "Open Connectors > Setup", Connectors, Form: "connectors"),
        new("guards", "Safety checks", false,
            "The safety checks hold back an unusual change (for example many tickets closed at once) until an Admin decides. Nothing should be left waiting.",
            "/Admin/Guards", "Open Guards (safety checks)", Guards, Fields: ["SI_Guards_Enabled"]),
        // operator 2026-10-09: "there must be one on/off. on = on for all" -- ONE switch, then the connection; the per-engine
        // switches are advanced overrides on the Settings page. The key itself goes into Key Vault (the page's key field).
        new("ai", "AI integration", false,
            "Turn AI integration on to let SecurityInsight use your own Azure OpenAI resource for every engine that has an AI step (classifying assets the rules cannot place, and AI summaries). Then give the endpoint and the deployment, and paste the key once: SecurityInsight stores it in your Key Vault and keeps only its name.",
            "/Admin/Settings?q=OpenAI", "Open Settings", Ai, Fields: [AiSwitch, "OpenAI_endpoint", "OpenAI_deployment", "OpenAI_apiKey"]),
    };

    /// The steps of a paid feature (Licensing/ProFeatures.cs): the licence itself, the role mapping, the CMDB, the connectors.
    /// Without a Pro licence they are not steps of this install (the free version, owner 2026-10-18) -- never red, never counted.
    public static bool IsProStep(GetStartedStep s) =>
        s.Id == "licence" || SI.Management.Web.Licensing.ProFeatures.ForPage(s.Href.Split('?', '#')[0]) is not null;

    /// Every step's check, computed now. A check that throws is open ("could not be checked") -- never done. <paramref name="pro"/>
    /// false (no Pro licence): the paid steps are left out.
    public static GetStartedResult Evaluate(GetStartedFacts facts, bool pro = true)
    {
        var list = new List<StepState>(Steps.Count);
        foreach (var s in Steps)
        {
            if (!pro && IsProStep(s)) continue;
            StepCheck c;
            try { c = s.Check(facts); }
            catch (Exception ex) when (ex is not OperationCanceledException) { c = new StepCheck(false, "could not be checked"); }
            var done = s.Checkable && c.Done;
            list.Add(new StepState(s, done, c.Note, !done && c.Waiting, !done && c.Problem, !done && c.Chosen));
        }
        return new GetStartedResult(list) { Facts = facts };
    }

    private const string NotRead = "could not be read right now";

    private static string Plural(long n, string one, string many) => Pages.Fmt.Int(n) + " " + (n == 1 ? one : many);

    // ---- waiting for the first run ------------------------------------------------------------------------------------

    /// How long a first full collection usually takes, in minutes (the same "about half an hour" the Run now text says).
    public const int FirstRunMinutes = 30;
    /// A run whose runner has not been heard from for this long is not "running" any more (the runner itself gives a
    /// silent run up after 15 minutes).
    public static readonly TimeSpan RunSilentAfter = TimeSpan.FromMinutes(30);

    /// No collection has completed on this install yet: what is open only waits for the first run.
    public static bool FirstRun(GetStartedFacts f) => f.Read("collections") && f.CompleteCollections == 0;

    /// An install on which "no run in the last 7 days" would be wrong: nothing has completed yet, or it is younger than
    /// the window the run records are read for.
    public static bool Young(GetStartedFacts? f) =>
        f is not null && (FirstRun(f) || (f.InstalledUtc is { } at && f.NowUtc - Pages.LocalTime.Utc(at) < TimeSpan.FromDays(RunDays)));

    /// "not run yet" on a young install, else "no run in the last 7 days".
    public static string NoRunText(GetStartedFacts? f) => Young(f) ? "not run yet" : "no run in the last " + RunDays + " days";

    /// "Waiting for the first run -- it started 2026-10-12 19:52 UTC and usually takes about 30 minutes" (the page shows
    /// the time in the viewer's zone), or "Waiting for the first run" while none has started.
    public static string WaitingForFirstRun(GetStartedFacts f) => f.RunStartedUtc is { } t
        ? "Waiting for the first run -- it started " + Pages.LocalTime.Text(t) + " and usually takes about " + Pages.Fmt.Int(FirstRunMinutes) + " minutes"
        : "Waiting for the first run";

    /// When the pipeline run in progress started; null when the newest run has ended, or its runner went silent.
    public static DateTime? RunningSince(SI.Management.Web.Jobs.FlowRun? run, DateTime nowUtc)
    {
        if (run is null || run.Finished || run.StartedUtc == DateTimeOffset.MinValue) return null;
        var heard = (run.HeartbeatUtc ?? run.StartedUtc).UtcDateTime;
        return nowUtc - heard > RunSilentAfter ? null : run.StartedUtc.UtcDateTime;
    }

    // ---- the checks ---------------------------------------------------------------------------------------------------

    /// What the step says while no licence check is on record: the licence is not guessed (never "missing", never an
    /// edition) -- the updater records what it verified, and the step closes by itself.
    public const string LicenceBeingChecked = "the licence is being checked -- SecurityInsight's updater records what it verified on its next run (every night), and this step closes by itself";

    public static StepCheck Licence(GetStartedFacts f)
    {
        if (!f.Read("licence")) return new(false, NotRead);
        if (f.Licence is not { } l) return new(false, LicenceBeingChecked, Waiting: true);
        var st = l.StateOn(f.NowUtc);
        var text = InstalledLicence.Describe(st).Text.ToLowerInvariant();
        var until = l.ValidTo is { } to ? " until " + InstalledLicence.Day(to) : "";
        // LICENCE-DIMENSION: the dimension first, as everywhere the edition is shown ("Pro Business (250 devices) -- valid until ...")
        var dim = LicenceDimension.Of(l, f.NowUtc) == LicenceDimension.Community ? "" : LicenceDimension.Text(l, f.NowUtc) + " -- ";
        return st is LicenceState.Valid or LicenceState.EndsSoon ? new(true, dim + text + until) : new(false, dim + text + until);
    }

    public static StepCheck Access(GetStartedFacts f)
    {
        if (!f.Read("access")) return new(false, NotRead);
        // #446: the Access page's assignments AND the roles given in Entra (the installer holds SuperAdmin there), once each
        var admins = f.Access.Where(a => a.Role is SiRole.Admin or SiRole.SuperAdmin).Select(a => (Id: a.PrincipalId.ToLowerInvariant(), Group: a.PrincipalType == AccessAssignment.Group))
            .Concat((f.EntraRoles ?? Array.Empty<SI.Management.Web.Auth.AppRoleHolder>()).Where(h => h.Role is "Admin" or "SuperAdmin" && h.Type is "User" or "Group")
                .Select(h => (Id: h.ObjectId, Group: h.Type == "Group")))
            .DistinctBy(x => x.Id).ToList();
        var groups = admins.Count(a => a.Group);
        var people = admins.Count - groups;
        // the installer holds SuperAdmin through Entra and is not listed here: "0 people" read as "nobody can manage it" (operator 2026-10-07)
        var note = people == 0 && groups == 0
            ? "nobody added yet -- only the person who installed SecurityInsight can manage it"
            : Plural(people, "person", "people") + (groups > 0 ? " and " + Plural(groups, "group", "groups") : "") + " with Admin or SuperAdmin";
        return new(people >= MinAdmins || groups > 0, note);
    }

    public static StepCheck Mail(GetStartedFacts f)
    {
        if (!f.Read("mail") || f.Mail is not { } m) return new(false, NotRead);
        // owner 2026-10-12: "No mail" is the install's own answer -- a finished choice, never an open step
        if (m.Mode.IsNone) return new(false, "no mail -- this install sends no mail, by choice; choose a shared mailbox or an SMTP relay below to turn it on", Chosen: true);
        if (m.Mode.IsSharedMailbox)
        {
            if (m.LastTest is { Failed: true }) return new(false, "shared mailbox: the last test mail failed", Problem: true);
            // ONE verdict (owner 2026-10-19 "otherwise remove that chk from the page and have only the one on get started"):
            // the step reads MailHealth -- the same verdict as the home banner and Settings > E-mail, from the stored
            // cfg.InstallState 'MailRestriction' -- never a check of its own: done exactly when the banner is not red
            return !m.Health.IsRed
                ? new(true, "shared mailbox, restriction verified" + (m.From is { Length: > 0 } fr ? " (" + fr + ")" : ""))
                : new(false, "shared mailbox: the restriction is not verified yet" + (m.Health.Reason is { Length: > 0 } why ? " -- " + why : ""));
        }
        if (m.Mode.IsSmtp)
        {
            if (m.LastTest is not { } t) return new(false, "SMTP relay: no test mail sent yet");
            if (t.Failed) return new(false, "SMTP relay: the last test mail failed", Problem: true);
            return t.Sent ? new(true, "SMTP relay, test mail sent") : new(false, "SMTP relay: the test mail is waiting for the mail job");
        }
        return new(false, "mail mode " + m.Mode.Mode);
    }

    public static StepCheck Sources(GetStartedFacts f)
    {
        if (!f.Read("runs")) return new(false, NotRead);
        var open = new List<string>();
        var notRun = new List<string>();
        var running = new List<string>();
        foreach (var e in SourceEngines)
        {
            var run = f.LatestRuns.FirstOrDefault(r => r.Engine.Equals(e, StringComparison.OrdinalIgnoreCase));
            var label = SourceLabel(e);
            if (run is null) notRun.Add(label);
            // owner 2026-10-11: a run in progress (or one stopped before its end) never reopens a step that is done -- the
            // daily collection would turn Get Started red every day; only a run that ENDED badly reopens it
            else if (!run.HasEnd) running.Add(label);
            else if (RunHealthModel.IsPartial(run.Row.ExitReason)) open.Add(label + ": incomplete");
            else if (RunHealthModel.IsDryRun(run.Row.ExitReason)) open.Add(label + ": only a dry run");
            else if (RunHealthModel.IsThrottled(run.Row.ExitReason)) open.Add(label + ": throttled by Microsoft -- it runs again automatically");
            else if (!RunHealthModel.IsOk(run.Row.ExitReason)) open.Add(label + ": failed (" + run.Row.ExitReason + ")");
        }
        var now = running.Count > 0 ? " (running now: " + string.Join(", ", running) + ")" : "";
        // owner 2026-10-12: nothing ended badly, and what is missing only waits for the first run (not started, or in
        // progress on an install where no run has finished yet) -- said as that, never as a list of "no run" lines
        if (open.Count == 0 && FirstRun(f) && (notRun.Count > 0 || running.Count > 0))
            return new(false, WaitingForFirstRun(f) + (f.RunStartedUtc is null ? now : ""), Waiting: true);
        open.AddRange(notRun.Select(l => l + ": " + NoRunText(f)));
        return open.Count == 0 ? new(true, "all four sources succeeded on their newest finished run" + now) : new(false, string.Join("; ", open) + now);
    }

    public static string SourceLabel(string engine) => engine switch
    {
        "identity" => "Identity",
        "azure" => "Azure",
        "endpoint" => "Endpoint",
        "publicip" => "Public IP",
        _ => engine,
    };

    public static StepCheck Collection(GetStartedFacts f)
    {
        if (!f.Read("collections")) return new(false, NotRead);
        return f.CompleteCollections > 0
            ? new(true, Plural(f.CompleteCollections, "complete collection", "complete collections") + " loaded" + (f.NewestCollectionUtc is { } t ? ", newest " + Pages.LocalTime.Text(t) : ""))
            : new(false, WaitingForFirstRun(f), Waiting: true);
    }

    public static StepCheck Tiers(GetStartedFacts f)
    {
        if (!f.Read("tiers")) return new(false, NotRead);
        var t0 = f.AssetsPerTier.TryGetValue("0", out var n) ? n : 0;
        var all = f.AssetsPerTier.Values.Sum();
        if (all == 0) return new(false, WaitingForFirstRun(f) + " (the assets and their tiers come with it)", Waiting: true);
        return t0 > 0 ? new(true, Plural(t0, "tier-0 asset", "tier-0 assets") + " of " + Plural(all, "asset", "assets"))
                      : new(false, "0 tier-0 assets of " + Plural(all, "asset", "assets"));
    }

    public static StepCheck Ring(GetStartedFacts f)
    {
        if (!f.Read("ring")) return new(false, NotRead);
        if (f.Ring is { } r) return new(true, "ring " + r.Ring + (r.Source is { } src ? " (set by " + src + ")" : ""));
        if (f.RingSetting is { } s) return new(true, "ring " + s + " (Settings)");
        return new(false, "no update ring recorded");
    }

    public static StepCheck Cmdb(GetStartedFacts f)
    {
        if (!f.Read("cmdb")) return new(false, NotRead);
        return f.ServicesWithMembers > 0
            ? new(true, Plural(f.ServicesWithMembers, "service", "services") + " with assets")
            : new(false, f.Services == 0 ? "no services yet" : Plural(f.Services, "service", "services") + ", none with assets yet");
    }

    /// A connector run that ended well: success, or a what-if run (nothing sent, by choice).
    public static bool RunOk(string? outcome) => outcome is "success" or "whatif";

    public static StepCheck Connectors(GetStartedFacts f)
    {
        if (!f.Read("connectors")) return new(false, NotRead);
        var enabled = f.Connectors.Where(c => c.Enabled).ToList();
        if (enabled.Count == 0) return new(false, f.Connectors.Count == 0 ? "no connector set up" : "no connector switched on");
        var open = new List<string>();
        foreach (var c in enabled)
        {
            var last = f.ConnectorRuns.Where(r => r.ConnectorName.Equals(c.Name, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(r => r.StartedAt ?? DateTime.MinValue).FirstOrDefault();
            if (last is null) open.Add(c.Name + ": not run yet");
            else if (!RunOk(last.Outcome)) open.Add(c.Name + ": last run " + last.Outcome);
        }
        return open.Count == 0 ? new(true, Plural(enabled.Count, "connector", "connectors") + ", last run ok") : new(false, string.Join("; ", open));
    }

    public static StepCheck Guards(GetStartedFacts f)
    {
        if (!f.Read("guards")) return new(false, NotRead);
        return f.OpenHolds == 0 ? new(true, "nothing held") : new(false, Plural(f.OpenHolds, "held change set waits", "held change sets wait") + " for a decision");
    }

    /// The Azure OpenAI connection every AI feature uses: endpoint, deployment and key all set (the key as a value or a
    /// Key Vault secret name).
    public static readonly IReadOnlyList<string> AiSettings = ["OpenAI_endpoint", "OpenAI_deployment", "OpenAI_apiKey"];

    /// The one AI switch: on = AI for every engine that has an AI step.
    public const string AiSwitch = "SI_EnableAI";

    /// The status in plain words (operator 2026-10-09: "msg is not understandable"): "AI is off", "AI is on -- connected
    /// to &lt;deployment&gt;", or "AI is on, but ... -- &lt;what to do&gt;". Done = on and every part of the connection set.
    public static StepCheck Ai(GetStartedFacts f)
    {
        if (!f.Read("settings")) return new(false, NotRead);
        var on = string.Equals(MailMode.Plain(MailMode.RowOf(f.Settings, AiSwitch)?.ValueJson)?.Trim(), "true", StringComparison.OrdinalIgnoreCase);
        if (!on) return new(false, "AI is off -- turn on AI integration below to use it");
        var missing = AiSettings.Where(n => !IsSet(f.Settings, n)).ToList();
        if (missing.Count == 0)
        {
            var dep = MailMode.Plain(MailMode.RowOf(f.Settings, "OpenAI_deployment")?.ValueJson)?.Trim();
            return new(true, "AI is on -- connected to " + (string.IsNullOrEmpty(dep) ? "your deployment" : dep));
        }
        if (missing.SequenceEqual(new[] { "OpenAI_apiKey" }))
            return new(false, "AI is on, but the key is not in Key Vault yet -- paste the Azure OpenAI key below and save; SecurityInsight stores it in your Key Vault");
        return new(false, "AI is on, but the " + string.Join(" and ", missing.Select(AiLabel)) + " " + (missing.Count == 1 ? "is" : "are") + " not set yet -- fill " + (missing.Count == 1 ? "it" : "them") + " in below");
    }

    private static string AiLabel(string name) => name switch
    {
        "OpenAI_endpoint" => "endpoint",
        "OpenAI_deployment" => "deployment",
        _ => "key",
    };

    private static bool IsSet(IReadOnlyList<SettingRow> rows, string name)
    {
        var row = MailMode.RowOf(rows, name);
        if (row is null) return false;
        if (!string.IsNullOrWhiteSpace(row.KeyVaultSecretName)) return true;
        return MailMode.Plain(row.ValueJson) is { } v && v.Trim().Length > 0;
    }
}
