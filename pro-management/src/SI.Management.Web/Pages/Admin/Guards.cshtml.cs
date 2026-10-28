using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Guards;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Operations &gt; Guards (safety checks) (#277): every time a safety check (a "guard") held, refused or stopped a step to
/// protect data. Server-side grid over cfg.GuardEvent (BRAND-2.7): search, a filter per column, sort, paging. Readers and
/// up may view (the page's policy).
/// EACH EVENT IN PLAIN WORDS (operator 2026-10-05: "i need more context for these things - cause, what to do,
/// consequence?"): the table is for scanning (When · What happened · Severity · Status · Action); each row expands to
/// What happened / Why / Consequence / What to do -- the catalog's templates filled from the event (GuardText), the same
/// words as the mail -- with the guard id as a small technical line.
/// WHAT "RELEASE" MEANS PER GUARD (operator 2026-10-05: "how can i release these guards"; the catalog's 'kind'):
///   release-held-set   "Release" -- the held closes / collection / hand-off batch of THAT run, once (cfg.GuardRelease);
///   release-collection "Release: load this collection anyway" -- a held Risk Analysis collection is loaded ONCE by the
///                      next data sync and MARKED PARTIAL wherever it is shown; the page shows exactly what was
///                      incomplete first, and a reason is required;
///   anything else      not releasable (fix the source / resolved by the next run / re-run / change a setting).
/// Every release is Admin only and audited; every event can be ACKNOWLEDGED (Admin, audited guard.event.acknowledge) and
/// acknowledged events -- and later repeats of exactly them -- are hidden by default.
/// </summary>
public sealed class GuardsModel : PageModel
{
    private readonly IGuardEventStore _store;
    private readonly GuardCatalog _catalog;
    private readonly ILogger<GuardsModel> _log;
    private readonly IGuardReleaseStore? _releases;
    private readonly IJobsClient? _jobs;
    private readonly SI.Management.Web.Audit.IChangeAttributionWriter? _attribution;
    private readonly ICollectionViews? _views;
    private readonly SI.Management.Web.ChangeJournal.ConfigSettings? _settings;
    private readonly SI.Management.Web.ChangeJournal.IConfigApprovalStore? _approvals;
    private readonly SettingsCatalog? _settingsCatalog;
    private readonly ISettingsStoreReader? _settingsReader;
    private readonly SettingsSaver? _saver;
    private readonly Microsoft.Extensions.Caching.Memory.IMemoryCache? _cache;
    public GuardsModel(IGuardEventStore store, GuardCatalog catalog, ILogger<GuardsModel> log, IGuardReleaseStore? releases = null, IJobsClient? jobs = null,
        SI.Management.Web.Audit.IChangeAttributionWriter? attribution = null, ICollectionViews? views = null,
        SI.Management.Web.ChangeJournal.ConfigSettings? settings = null, SI.Management.Web.ChangeJournal.IConfigApprovalStore? approvals = null,
        SettingsCatalog? settingsCatalog = null, ISettingsStoreReader? settingsReader = null, SettingsSaver? saver = null,
        Microsoft.Extensions.Caching.Memory.IMemoryCache? cache = null, GuardModeReader? guardMode = null)
    {
        _store = store; _catalog = catalog; _log = log; _releases = releases; _jobs = jobs; _attribution = attribution; _views = views; _settings = settings; _approvals = approvals;
        _settingsCatalog = settingsCatalog; _settingsReader = settingsReader; _saver = saver; _cache = cache; _guardMode = guardMode;
    }
    private readonly GuardModeReader? _guardMode;

    /// CR4 (#654): the stricter period after a release that changed engine code -- shown read-only with the limits
    /// "configured -> effective while strict"; a SuperAdmin may end it early with a reason (audited guard.strict.end-early).
    public GuardModeState Mode { get; private set; } = GuardModeState.Normal;
    public bool MayEndStrict => User.IsSuperAdmin() && Mode.IsStrict;

    /// PURE over the page's settings: the configured value of a numbered limit (its stored value, else the catalog default).
    public double? ConfiguredOf(string name)
    {
        var f = Field(name);
        var text = f?.Text;
        return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
    }

    /// "5 while strict" beside a limit in Control; '' when not strict.
    public string StrictHint(string name) =>
        Mode.IsStrict && ConfiguredOf(name) is { } c && GuardModeRules.Effective(c, Mode) is var e && e != c
            ? string.Create(CultureInfo.InvariantCulture, $"{e:0.##} while strict") : "";

    [BindProperty] public string? StrictReason { get; set; }

    /// CR4 (#654): a SuperAdmin ends the stricter period early, with a reason -- the normal limits apply from then on.
    /// Written through cfg.GuardStrictEndSet only; audited with the reason and the period it ended.
    [SI.Management.Web.Audit.Audited("guard.strict.end-early")]
    public async Task<IActionResult> OnPostEndStrictAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        var audit = SI.Management.Web.Audit.AuditScope.Current;
        if (audit is not null) audit.Target = "/Admin/Guards/stricter-period";
        var reason = (StrictReason ?? "").Trim();
        string message; var ok = false;
        try
        {
            if (_guardMode is null) throw new InvalidOperationException("the guard mode cannot be read in this installation");
            _guardMode.Forget();
            var now = await _guardMode.ReadAsync(ct);
            if (!now.IsStrict) { message = "Nothing to end: the safety checks are not in a stricter period."; audit?.Refused(message); }
            else if (reason.Length < GuardModeRules.ReasonMin) { message = $"Give a reason of at least {GuardModeRules.ReasonMin} characters."; audit?.Refused(message); }
            else
            {
                await _guardMode.EndEarlyAsync(now, Me, "SuperAdmin", reason, ct);
                if (audit is not null)
                {
                    audit.Reason = reason;
                    audit.BeforeJson = System.Text.Json.JsonSerializer.Serialize(new { mode = "strict", until = GuardModeRules.Iso(now.Until), release = now.Version });
                    audit.AfterJson = System.Text.Json.JsonSerializer.Serialize(new { mode = "normal", endedEarly = true, by = Me, role = "SuperAdmin" });
                }
                message = "The stricter period is ended: the normal limits apply again from now on.";
                ok = true;
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            message = "Not ended: " + ex.Message; audit?.Refused(ex.Message);
        }
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        return Redirect(Link(("handler", null)) + "#gstrict-h");
    }

    /// One held set the page lists under "Held now": ONE row per check (operator 2026-10-09: "this is way too complex"),
    /// one plain sentence, one Release.
    public sealed record HeldItem(GuardCatalog.Entry Guard, GuardRelease Rel);

    /// The newest collection the web app shows (UTC): a held collection at or before it is superseded and not shown.
    public DateTime? NewestLoadedUtc { get; private set; }

    /// ONLY CURRENT HOLDS (#448): per check and connector the NEWEST held set (or a released one waiting for its run) that
    /// has not expired; a held collection is not shown at all once a newer collection is loaded. The jobs close the older
    /// ones on their next run (guard.release.supersede); the page never shows them meanwhile.
    public IReadOnlyList<HeldItem> HeldNow()
    {
        var now = DateTime.UtcNow;
        return AllReleases.Where(r => r.State is "held" or "released" && r.ExpiresUtc is { } e && e > now)
            .Where(r => !(r.IsCollection && r.State == "held" && NewestLoadedUtc is { } nl && r.CollectionTime is { } ct && ct <= nl))
            .GroupBy(r => (r.GuardId, r.Connector))
            .Select(g => g.OrderByDescending(r => r.State == "released").ThenByDescending(r => r.CollectionTime ?? r.HeldUtc).ThenByDescending(r => r.Id).First())
            .Select(r => (_catalog.Find(r.GuardId), r)).Where(x => x.Item1 is not null)
            .Select(x => new HeldItem(x.Item1!, x.r)).OrderByDescending(x => x.Rel.HeldUtc).ToList();
    }

    /// CONTROL (operator 2026-10-09: "for a simple solution that pulls data and sync data to connectors"): ONE switch for
    /// every safety check, TWO limits and ONE mail switch with its recipients -- the same settings Settings &gt; Guards
    /// edits. Every other check is internal: it warns (badge and mail) and is not configurable here; a per-check switch an
    /// install already set is still read by the engines (an off check stays off), it is just not shown.
    public static readonly IReadOnlyList<string> ControlSettings =
        [GuardSwitches.Master, "SI_VulnSync_MaxClosePercent", "SI_AssetProperties_ChangeGuardPercent", "SI_GuardMail_Enabled", "SI_GuardMail_To"];
    public IReadOnlyDictionary<string, SettingField> ControlFields { get; private set; } = new Dictionary<string, SettingField>();
    public SettingField? Field(string name) => ControlFields.TryGetValue(name, out var f) ? f : null;
    /// Whether the safety checks are on (SI_Guards_Enabled).
    public bool MasterOn { get; private set; } = true;
    /// Changing the safety checks is a SuperAdmin's (everyone who may open the page sees the state).
    public bool MayControl => User.IsSuperAdmin();

    private async Task LoadControlsAsync(CancellationToken ct)
    {
        if (_settingsCatalog is null || _settingsReader is null) return;
        try
        {
            var (rows, _) = await _settingsReader.ReadSettingsAsync(ct);
            var all = rows.ToLookup(r => r.Name, StringComparer.OrdinalIgnoreCase);
            var d = new Dictionary<string, SettingField>(StringComparer.OrdinalIgnoreCase);
            foreach (var n in ControlSettings)
                if (_settingsCatalog.Find(n) is { } s) d[n] = SettingsLayout.Field(s, all[s.Name].ToList(), _settingsCatalog, all);
            ControlFields = d;
            // the master alone: IsOn over its row only, for an id no guard has (so only the master can turn it off)
            MasterOn = GuardSwitches.IsOn(rows.Where(r => r.Name.Equals(GuardSwitches.Master, StringComparison.OrdinalIgnoreCase)).ToList(), "master.only.switch");
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the guard settings could not be read for Control"); }
    }

    /// Control: the switch, the two limits and the mail, saved through the ONE settings save (SettingsSaver: validation, the
    /// version check, the change log; before / after on this request's audit row). SuperAdmin only.
    [SI.Management.Web.Audit.Audited("guard.control.save")]
    public async Task<IActionResult> OnPostSaveControlAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        try
        {
            if (SI.Management.Web.Audit.AuditScope.Current is { } a0) a0.Target = "/Admin/Guards/control";
            if (_saver is null) throw new InvalidOperationException("the settings cannot be saved in this installation");
            var names = ControlSettings.Where(n => _settingsCatalog?.Find(n) is not null).ToList();
            var r = await _saver.SaveAsync(Request.Form, names, User, "/Admin/Guards/control", ct);
            _cache?.Remove("si-guard-switches");
            TempData["toast"] = r.Ok ? (r.Saved == 0 ? "Nothing changed." : r.Message) : r.Message;
            TempData["toastKind"] = r.Ok ? "ok" : "error";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            SI.Management.Web.Audit.AuditScope.Current?.Refused(ex.Message);
            TempData["toast"] = "Not saved: " + ex.Message;
            TempData["toastKind"] = "error";
        }
        return Redirect(Link(("handler", null)) + "#gctl-h");
    }

    /// The held sets of the period, by the run that held them (the guard event's RunId).
    public IReadOnlyDictionary<string, GuardRelease> Releases { get; private set; } = new Dictionary<string, GuardRelease>();
    /// The held Risk Analysis collections (kind 'collection'), newest first.
    public IReadOnlyList<GuardRelease> HeldCollections { get; private set; } = Array.Empty<GuardRelease>();
    /// Every held set of the period (both kinds), for the guards' state (GUARD-1.6: what each guard holds right now).
    public IReadOnlyList<GuardRelease> AllReleases { get; private set; } = Array.Empty<GuardRelease>();
    /// Guard releases waiting for a second SuperAdmin (CONFIG-1.5), and recently decided ones.
    public IReadOnlyList<SI.Management.Web.ChangeJournal.ConfigApproval> Approvals { get; private set; } = Array.Empty<SI.Management.Web.ChangeJournal.ConfigApproval>();
    public bool SecondPerson { get; private set; }
    /// ?release=&lt;run id&gt; -- the link in the guard mail: that set is opened.
    [BindProperty(SupportsGet = true, Name = "release")] public string? ReleaseRun { get; set; }
    [BindProperty] public long ReleaseId { get; set; }
    [BindProperty] public long EventId { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// GUARD-1.6: the plan the SuperAdmin saw (its hash), and how long the release lasts: the next run, or a number of hours (at most 24).
    [BindProperty] public string? PlanHash { get; set; }
    [BindProperty] public string? Valid { get; set; }
    [BindProperty] public int Hours { get; set; } = GuardRelease.MaxReleaseHours;
    [BindProperty] public long ApprovalId { get; set; }
    [BindProperty] public bool Approve { get; set; }
    /// GUARD-1.6: releasing a guard is a SuperAdmin's (an Admin sees what is held and acknowledges).
    public bool MayRelease => User.IsSuperAdmin();
    public string Me => User.ChangeName();

    /// GUARD-1.6: every guard of the catalog, whether it holds something right now (and what), and when it last tripped.
    public sealed record GuardState(GuardCatalog.Entry Guard, bool Holding, string Holds, DateTime? LastTripUtc);

    public IReadOnlyList<GuardState> States()
    {
        var now = DateTime.UtcNow;
        return _catalog.Guards.Select(g =>
        {
            var held = AllReleases.Where(r => r.GuardId == g.Id && r.State is "held" or "released" && r.ExpiresUtc is { } e && e > now).ToList();
            var holds = held.Count == 0 ? "" : string.Join("; ", held.Select(r => r.IsCollection
                ? GuardReleaseText.Sentence(r) + (r.State == "released" ? " Released." : "")
                : GuardReleaseText.Sentence(r) + (r.State == "released" ? " Released." : "")));
            var last = Rows.Where(x => x.GuardId == g.Id && !x.IsClear && !x.IsTaken).Select(x => x.TsUtc).Max();   // a clear is not a trip
            return new GuardState(g, held.Count > 0, holds, last);
        }).ToList();
    }
    public bool MayAcknowledge => User.IsAdmin() && CanAcknowledge;
    public bool CanAcknowledge { get; private set; }
    /// The newest collection the web app shows, as text (the {latest} placeholder).
    public string? Latest { get; private set; }

    public GuardRelease? ReleaseFor(GuardRow r) => r.RunId is { Length: > 0 } id && Releases.TryGetValue(id, out var x) && !x.IsCollection ? x : null;

    /// The held collections a 'datasync.collection.held' event is about: those held by then (and still listed).
    public IReadOnlyList<GuardRelease> CollectionsFor(GuardRow r) =>
        _catalog.Find(r.GuardId)?.Kind != GuardKinds.ReleaseCollection ? Array.Empty<GuardRelease>()
            : HeldCollections.Where(c => r.TsUtc is null || c.HeldUtc is null || c.HeldUtc <= r.TsUtc.Value.AddMinutes(10)).ToList();

    public GuardParts Parts(GuardRow r) => GuardText.Parts(_catalog.Find(r.GuardId), r, Latest);
    public string KindOf(GuardRow r) => _catalog.Find(r.GuardId)?.Kind ?? GuardKinds.Info;

    /// The Status column: acknowledged, released (and what came of it), or open.
    public string StatusOf(GuardRow r)
    {
        if (r.Acknowledged) return "Acknowledged" + (string.IsNullOrEmpty(r.AckBy) ? "" : " by " + r.AckBy);
        // owner 2026-10-17: a clear, a trip a later clear closed, a trip the owner accepted for its version
        if (r.IsTaken) return "Taken as the new level (not back to normal)";
        if (r.Taken) return "Taken as the new level: " + (r.ClearedText ?? "");
        if (r.IsClear) return "Cleared";
        if (r.Cleared) return "Cleared" + (string.IsNullOrEmpty(r.ClearedText) ? "" : ": " + r.ClearedText);
        if (r.Accepted) return "Accepted by the owner for this version";
        if (ReleaseFor(r) is { } rel && rel.State != "held") return "Released" + (rel.State == "applied" ? ", applied" : rel.State == "expired" ? " (expired)" : ", waiting for the next run");
        var cols = CollectionsFor(r);
        if (cols.Count > 0 && cols.All(c => c.State != "held")) return "Released" + (cols.All(c => c.State == "applied") ? ", loaded (partial)" : ", loads with the next data sync");
        return "Open";
    }

    public static readonly (string Value, string Label)[] Windows = [("1", "Last day"), ("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days"), ("all", "All time")];
    public static readonly IReadOnlyList<string> MailStates = ["sent", "deduped", "pending", "off", "no-recipients", "no-relay", "failed", "accepted"];
    public static readonly IReadOnlyList<string> TelemetryStates = ["sent", "pending", "off", "halted", "failed", "no-install-id", "test-session", "accepted"];
    public static readonly IReadOnlyList<string> Severities = ["critical", "warning", "info"];
    public static readonly IReadOnlyList<string> AckStates = ["open", "acknowledged", "cleared", "taken", "accepted"];

    [BindProperty(SupportsGet = true)] public string? Win { get; set; }
    /// ?ack=all shows acknowledged events too (default: open only).
    [BindProperty(SupportsGet = true)] public string? Ack { get; set; }
    public bool ShowAcknowledged => string.Equals(Ack, "all", StringComparison.OrdinalIgnoreCase);

    public bool HasTable { get; private set; }
    public IReadOnlyList<GuardRow> Rows { get; private set; } = Array.Empty<GuardRow>();
    public long Total { get; private set; }
    public GridState? State { get; private set; }
    public string Query { get; private set; } = SqlGuardEventStore.ExistsSql;
    public string? Error { get; private set; }
    public GuardCatalog Catalog => _catalog;
    public string WindowValue => Win is { Length: > 0 } w && Windows.Any(x => x.Value == w) ? w : "30";

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            HasTable = await _store.ExistsAsync(ct);
            if (!HasTable) return;
            CanAcknowledge = await _store.CanAcknowledgeAsync(ct);
            var st = State = GridState();
            DateTime? from = WindowValue == "all" ? null : DateTime.UtcNow.AddDays(-int.Parse(WindowValue, CultureInfo.InvariantCulture));
            (Rows, Total, Query) = await _store.PageAsync(st, from, ct);
            await LoadReleasesAsync(ct);
            await LoadLatestAsync(ct);
            await LoadControlsAsync(ct);
            if (_guardMode is not null) Mode = await _guardMode.ReadAsync(ct);
            CheckReleaseLink();
        }
        catch (ArgumentException ex) { Error = ex.Message; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the guard events failed");
            Error = "The guard events could not be read: " + ex.Message;
        }
    }

    private async Task LoadReleasesAsync(CancellationToken ct)
    {
        if (_releases is null) return;
        try
        {
            var d = new Dictionary<string, GuardRelease>(StringComparer.OrdinalIgnoreCase);
            var recent = await _releases.RecentAsync(ct);
            foreach (var r in recent) d.TryAdd(r.RunId, r);
            Releases = d;
            AllReleases = recent;
            if (_settings is not null) SecondPerson = (await _settings.ReadAsync(ct)).SecondPerson;
            if (_approvals is not null) Approvals = await _approvals.RecentAsync(SI.Management.Web.ChangeJournal.ConfigApproval.GuardRelease, ct);
            HeldCollections = recent.Where(r => r.IsCollection).OrderByDescending(r => r.CollectionTime ?? r.HeldUtc).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the held sets could not be read"); }
    }

    private async Task LoadLatestAsync(CancellationToken ct)
    {
        // the newest collection is read whenever a collection is held (only current holds) or a text names it
        if (_views is null || (!AllReleases.Any(r => r.IsCollection) && !Rows.Any(r => (_catalog.Find(r.GuardId)?.Consequence ?? "").Contains("{latest}", StringComparison.Ordinal)))) return;
        try
        {
            var newest = (await _views.CollectionsAsync(ct)).Data.OrderByDescending(c => c.CollectionTime).FirstOrDefault();
            if (newest is not null)
            {
                Latest = newest.CollectionTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
                NewestLoadedUtc = DateTime.SpecifyKind(newest.CollectionTime, DateTimeKind.Utc);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the newest collection could not be read for the guard texts"); }
    }

    /// The least a reason must say (a person reads it later on the audit trail).
    public const int ReasonMin = 10;

    /// GUARD-1.6 -- a release is explicit and narrow: ONE guard and ONE scope (the held set of one run, or one held
    /// collection), the exact plan the SuperAdmin saw (its hash: a changed plan needs a new release), for the next run only
    /// or until a time of at most 24 hours, with a reason; it ends by itself. SuperAdmin only; audited with the request's
    /// correlation id. With SIWeb_ConfigSecondPerson on, it waits for ANOTHER SuperAdmin (CONFIG-1.5).
    private async Task<(GuardRelease Rel, string Why, int Hours, string Scope)> CheckReleaseAsync(bool collection, CancellationToken ct)
    {
        if (_releases is null) throw new InvalidOperationException("held sets are not available in this installation");
        // operator 2026-10-09: the reason is optional -- left empty it reads "Released by <name>"; a reason typed in says why
        var why = (Reason ?? "").Trim();
        if (why.Length == 0) why = "Released by " + Me;
        if (why.Length < ReasonMin) throw new ArgumentException($"a reason, when you give one, says why in a few words (at least {ReasonMin} characters) -- or leave it empty");
        if (why.Length > 1000) why = why[..1000];
        var rel = await _releases.FindAsync(ReleaseId, ct) ?? throw new ArgumentException(collection ? "that held collection does not exist" : "that held set does not exist");
        if (collection && !rel.IsCollection) throw new ArgumentException("that is not a held collection");
        if (!collection && rel.IsCollection) throw new ArgumentException("a held collection is released with Release: load this collection anyway");
        if (_catalog.Find(rel.GuardId) is { Releasable: false } g) throw new ArgumentException($"{g.Id} can never be released: {g.NeverReleasable}");
        if (!rel.CanRelease(DateTime.UtcNow))
            throw new InvalidOperationException(rel.State == "held" ? "it has expired (a held set can be released for 7 days)" : $"it is already {rel.State}");
        if (string.IsNullOrEmpty(rel.PlanHash)) throw new InvalidOperationException("this database has no plan hash for held sets yet (apply sql\\si-pro-settings.sql -- it only adds)");
        if (!string.Equals(PlanHash, rel.PlanHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("what is held changed since you looked -- open it again and release the plan as it is now");
        var scope = string.Equals(Valid, "hours", StringComparison.OrdinalIgnoreCase) ? "until" : "run";
        var hours = scope == "until" ? Math.Clamp(Hours, 1, GuardRelease.MaxReleaseHours) : GuardRelease.MaxReleaseHours;
        return (rel, why, hours, scope);
    }

    /// Releases the set now (no approval needed, or approved by <paramref name="approvedBy"/>), records who asked for it for
    /// the job that applies it, and starts that job. Returns the toast.
    private async Task<string> ReleaseNowAsync(GuardRelease rel, string by, string why, int hours, string scope, string? approvedBy, CancellationToken ct)
    {
        var until = rel.ReleaseUntil(DateTime.UtcNow, hours);
        var cid = SI.Management.Web.Audit.AuditScope.Current?.CorrelationId;
        if (!await _releases!.ReleaseAsync(rel.Id, by, why, rel.PlanHash!, until, scope, cid, approvedBy, ct))
            throw new InvalidOperationException("it was released, expired or changed in the meantime");
        var what = rel.IsCollection
            ? $"the Risk Analysis collection of {(rel.CollectionTime is { } t ? t.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : rel.RunId)} loaded once, marked partial"
            : GuardReleaseText.IfRelease(rel);
        if (SI.Management.Web.Audit.AuditScope.Current is { } a)
        {
            a.Target = rel.IsCollection ? rel.RunId : "release/" + rel.RunId;
            a.Reason = why;
            a.AfterJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                guard = rel.GuardId, scope = rel.Connector + "/" + rel.RunId, held = rel.HeldCount, planHash = rel.PlanHash, validFor = scope == "run" ? "the next run" : $"until {until:yyyy-MM-dd HH:mm} UTC",
                untilUtc = until, approvedBy, collection = rel.IsCollection ? rel.CollectionTime : null, findings = rel.IsCollection ? rel.CollectionRows : (long?)null,
                heldBecause = rel.HoldReason, incomplete = rel.RunDetail, markedPartial = rel.IsCollection ? true : (bool?)null,
            });
        }
        // #302 (AUDIT-1.1): the job that applies the release -- now or at its next run -- names who released it (and the approver)
        if (_attribution is not null)
            await _attribution.RecordAsync(SI.Management.Web.Audit.ChangeAttribution.CorrelationId(),
                [new SI.Management.Web.Audit.AttributionEntry(rel.IsCollection ? rel.RunId : "release/" + rel.RunId, by, SI.Management.Web.Audit.AttributionKinds.Release, SI.Management.Web.Audit.AttributionOps.Approve) { Title = what, ApprovedBy = approvedBy }], ct);
        string started;
        if (_jobs is { IsConfigured: true })
        {
            var env = rel.IsCollection ? new Dictionary<string, string>() : new Dictionary<string, string> { ["SI_VulnSync_ReleaseRunId"] = rel.RunId, ["SI_VulnSync_ReleasedBy"] = by };
            try { started = " " + rel.Job + " was started to apply it now (" + await _jobs.StartWithEnvAsync(rel.Job, env, ct) + ")."; }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the job could not be started"); started = " It applies with the job's next run (the job could not be started now)."; }
        }
        else started = " It applies with the job's next run.";
        var window = scope == "run" ? $"for the next run only (at the latest until {Fmt.When(until)})" : $"until {Fmt.When(until)}";
        return (rel.IsCollection
            ? $"Released once, {window}: the collection is loaded and MARKED PARTIAL wherever it is shown."
            : $"Released, {window}: " + GuardReleaseText.IfRelease(rel)) + started;
    }

    /// Asks a second SuperAdmin (CONFIG-1.5): the release waits on this page until another SuperAdmin approves or rejects it.
    private async Task<string> RequestApprovalAsync(GuardRelease rel, string why, int hours, string scope, CancellationToken ct)
    {
        if (_approvals is null) throw new InvalidOperationException("this installation cannot record approvals");
        var payload = new System.Text.Json.Nodes.JsonObject { ["releaseId"] = rel.Id, ["planHash"] = rel.PlanHash, ["hours"] = hours, ["scope"] = scope };
        var title = "Release: " + GuardReleaseText.Sentence(rel);
        var id = await _approvals.RequestAsync(SI.Management.Web.ChangeJournal.ConfigApproval.GuardRelease, title, payload.ToJsonString(), why, Me, SI.Management.Web.Audit.AuditScope.Current?.CorrelationId, ct);
        if (SI.Management.Web.Audit.AuditScope.Current is { } a)
        {
            a.Action = "config.approval.request";
            a.Target = "/Admin/Guards/approval/" + id.ToString(CultureInfo.InvariantCulture);
            a.Reason = why;
            a.AfterJson = System.Text.Json.JsonSerializer.Serialize(new { kind = "guard-release", guard = rel.GuardId, run = rel.RunId, planHash = rel.PlanHash, scope, hours });
        }
        return $"Sent for approval (request #{id}): another SuperAdmin approves or rejects it on this page. Nothing is released yet.";
    }

    /// "Release": THAT run's held set (a close set, an asset-properties change, a CMDB hand-off batch), once.
    [SI.Management.Web.Audit.Audited("guard.release.approve")]
    public async Task<IActionResult> OnPostReleaseAsync(CancellationToken ct) => await ReleaseAsync(false, ct);

    /// "Release: load this collection anyway": THAT held Risk Analysis collection is loaded once by the next data sync and
    /// MARKED PARTIAL wherever it is shown.
    [SI.Management.Web.Audit.Audited("guard.collection.release")]
    public async Task<IActionResult> OnPostReleaseCollectionAsync(CancellationToken ct) => await ReleaseAsync(true, ct);

    private async Task<IActionResult> ReleaseAsync(bool collection, CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        try
        {
            var (rel, why, hours, scope) = await CheckReleaseAsync(collection, ct);
            var second = _settings is not null && (await _settings.ReadAsync(ct)).SecondPerson;
            TempData["toast"] = second ? await RequestApprovalAsync(rel, why, hours, scope, ct) : await ReleaseNowAsync(rel, Me, why, hours, scope, null, ct);
            TempData["toastKind"] = "ok";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            SI.Management.Web.Audit.AuditScope.Current?.Refused(ex.Message);
            TempData["toast"] = "Not released: " + ex.Message;
            TempData["toastKind"] = "error";
        }
        return Redirect(Link());
    }

    /// A second SuperAdmin approves (the release then happens: released by the requester, approved by this SuperAdmin) or
    /// rejects a guard release someone else asked for. The requester can never approve their own.
    [SI.Management.Web.Audit.Audited("config.approval.decide")]
    public async Task<IActionResult> OnPostDecideAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        try
        {
            if (_approvals is null || _releases is null) throw new InvalidOperationException("this installation cannot record approvals");
            var req = await _approvals.FindAsync(ApprovalId, ct) ?? throw new ArgumentException("that request does not exist");
            if (SI.Management.Web.Audit.AuditScope.Current is { } a0) { a0.Target = "/Admin/Guards/approval/" + req.Id.ToString(CultureInfo.InvariantCulture); a0.Reason = Reason; a0.AfterJson = System.Text.Json.JsonSerializer.Serialize(new { approve = Approve, kind = req.Kind, requestedBy = req.RequestedBy }); }
            if (req.Kind != SI.Management.Web.ChangeJournal.ConfigApproval.GuardRelease) throw new ArgumentException("that request is not a guard release");
            if (!req.MayDecide(Me, DateTime.UtcNow)) throw new ArgumentException(string.Equals(req.RequestedBy, Me, StringComparison.OrdinalIgnoreCase) ? "you asked for it -- another SuperAdmin decides" : "it is no longer waiting (decided or expired)");
            var p = System.Text.Json.Nodes.JsonNode.Parse(req.PayloadJson) as System.Text.Json.Nodes.JsonObject ?? throw new ArgumentException("the request cannot be read");
            var rel = await _releases.FindAsync(p["releaseId"]?.GetValue<long>() ?? 0, ct) ?? throw new ArgumentException("the held set no longer exists");
            if (!await _approvals.DecideAsync(req.Id, Approve, Me, string.IsNullOrWhiteSpace(Reason) ? null : Reason.Trim(), ct)) throw new InvalidOperationException("it was decided or expired in the meantime");
            if (!Approve)
            {
                await _approvals.SetOutcomeAsync(req.Id, "rejected", "rejected by " + Me, ct);
                TempData["toast"] = $"Rejected: request #{req.Id} of {req.RequestedBy}. Nothing was released.";
                TempData["toastKind"] = "ok";
                return Redirect(Link());
            }
            // the plan must still be the one the requester saw (GUARD-1.6)
            if (!rel.CanRelease(DateTime.UtcNow) || !string.Equals(rel.PlanHash, p["planHash"]?.GetValue<string>(), StringComparison.OrdinalIgnoreCase))
            {
                await _approvals.SetOutcomeAsync(req.Id, "failed", "the held set changed, expired or was released since it was asked for -- nothing was released", ct);
                throw new InvalidOperationException("the held set changed, expired or was released since it was asked for -- nothing was released; ask again");
            }
            var text = await ReleaseNowAsync(rel, req.RequestedBy, req.Reason ?? req.Title, p["hours"]?.GetValue<int>() ?? GuardRelease.MaxReleaseHours, p["scope"]?.GetValue<string>() ?? "run", Me, ct);
            await _approvals.SetOutcomeAsync(req.Id, "applied", $"approved by {Me}: {text}", ct);
            TempData["toast"] = $"Approved: {text}";
            TempData["toastKind"] = "ok";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            SI.Management.Web.Audit.AuditScope.Current?.Refused(ex.Message);
            TempData["toast"] = "Not done: " + ex.Message;
            TempData["toastKind"] = "error";
        }
        return Redirect(Link());
    }

    /// "Acknowledge": the event (and later repeats of exactly it) is read and hidden by default. Admin only; audited.
    [SI.Management.Web.Audit.Audited("guard.event.acknowledge")]
    public async Task<IActionResult> OnPostAcknowledgeAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        try
        {
            if (SI.Management.Web.Audit.AuditScope.Current is { } a0) a0.Target = "/Admin/Guards/event/" + EventId.ToString(CultureInfo.InvariantCulture);
            var ev = await _store.FindAsync(EventId, ct) ?? throw new ArgumentException("that guard event does not exist");
            var note = string.IsNullOrWhiteSpace(Reason) ? null : Reason.Trim();
            if (SI.Management.Web.Audit.AuditScope.Current is { } a) { a.Target = "/Admin/Guards/event/" + ev.Id.ToString(CultureInfo.InvariantCulture); a.Reason = note ?? $"{ev.GuardId} read"; }
            var outcome = await _store.AcknowledgeAsync(ev.Id, User.ChangeName(), note, ct);
            switch (outcome)
            {
                case "Acknowledged":
                    TempData["toast"] = "Acknowledged: the event is hidden (Show acknowledged lists it). Repeats of exactly this event are hidden too; anything new shows again.";
                    TempData["toastKind"] = "ok";
                    break;
                case "Already":
                    TempData["toast"] = "It was already acknowledged.";
                    TempData["toastKind"] = "ok";
                    break;
                case "NoTable":
                    throw new InvalidOperationException("this database cannot record acknowledgements yet (apply sql\\si-pro-settings.sql -- it only adds)");
                default:
                    throw new ArgumentException("that guard event does not exist");
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            SI.Management.Web.Audit.AuditScope.Current?.Refused(ex.Message);
            TempData["toast"] = "Not acknowledged: " + ex.Message;
            TempData["toastKind"] = "error";
        }
        return Redirect(Link());
    }

    public IReadOnlyList<string> Options(GridColumn c) => c.Key switch
    {
        "Guard" => _catalog.Guards.Select(g => g.Id).ToList(), "Area" => _catalog.Areas, "Outcome" => _catalog.Outcomes, "Severity" => Severities,
        "Mail" => MailStates, "Telemetry" => TelemetryStates, "Ack" => AckStates, _ => Array.Empty<string>(),
    };

    /// #287: the events per choice of one column filter, under the OTHER filters and the time window (read when opened).
    public async Task<IActionResult> OnGetValueCountsAsync(string? col, CancellationToken ct)
    {
        try
        {
            if (!await _store.ExistsAsync(ct) || SqlGuardEventStore.Spec.Column(col) is not { Filter: GridFilter.Values or GridFilter.Tokens } c)
                return new JsonResult(new { ok = false });
            DateTime? from = WindowValue == "all" ? null : DateTime.UtcNow.AddDays(-int.Parse(WindowValue, CultureInfo.InvariantCulture));
            var counts = await _store.ValueCountsAsync(GridState(), from, c.Key, ct);
            return new JsonResult(new { ok = true, column = c.Key, values = counts.Select(x => new { value = x.Value, n = x.N, text = Fmt.Int(x.N) }) });
        }
        catch (ArgumentException ex) { return new JsonResult(new { ok = false, message = ex.Message }); }
    }

    public GridState GridState() => GridState(null, null, false);

    /// The grid of the current URL; <paramref name="openOnly"/> forces the Status filter to open (Acknowledge all).
    private GridState GridState(int? page, int? size, bool openOnly)
    {
        var q = Request.Query;
        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in q)
        {
            if (!kv.Key.StartsWith("f.", StringComparison.OrdinalIgnoreCase)) continue;
            var joined = string.Join("|", kv.Value.Where(v => !string.IsNullOrWhiteSpace(v)));
            if (joined.Length > 0) filters[kv.Key[2..]] = joined;
        }
        // operator 2026-10-07 ("state default should select holding only"): the Status filter defaults to OPEN -- not
        // acknowledged; ?ack=all (or a Status filter in the URL) widens it, and the choice stays in the URL
        if (!ShowAcknowledged && !filters.ContainsKey("Ack")) filters["Ack"] = "open";
        if (openOnly) filters["Ack"] = "open";
        var dir = (string?)q["dir"];
        return GridSql.Normalize(SqlGuardEventStore.Spec, new GridRequest
        {
            Sort = q["sort"], Desc = dir is "desc" ? true : dir is "asc" ? false : null,
            Page = page ?? (int.TryParse(q["p"], NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : 1),
            Size = size ?? GridSql.PageSize((string?)q["size"]),
            Search = q["q"], Filters = filters,
        });
    }

    /// The most events one "Acknowledge all" acknowledges (a bound, not a cap on what is shown: the rest stay open and a
    /// second click acknowledges them).
    public const int AcknowledgeAllMax = 5000;

    /// "Acknowledge all" (operator 2026-10-07: "close all/acknowledge all so i can start a fresh"): every OPEN event of the
    /// current filter and time window is acknowledged -- one reason, SuperAdmin only, the same acknowledgement as one event
    /// (cfg.GuardAck), audited as guard.event.acknowledge with every id. Nothing is released: a held set or collection stays
    /// held (releases are one at a time on purpose).
    [SI.Management.Web.Audit.Audited("guard.event.acknowledge")]
    public async Task<IActionResult> OnPostAcknowledgeAllAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        var back = Link(("handler", null));
        try
        {
            if (SI.Management.Web.Audit.AuditScope.Current is { } a0) a0.Target = "/Admin/Guards/events";
            var why = (Reason ?? "").Trim();
            if (why.Length < ReasonMin) throw new ArgumentException($"say why every open event is acknowledged (at least {ReasonMin} characters)");
            if (why.Length > 1000) why = why[..1000];
            if (!await _store.CanAcknowledgeAsync(ct)) throw new InvalidOperationException("this database cannot record acknowledgements yet (apply sql\\si-pro-settings.sql -- it only adds)");
            DateTime? from = WindowValue == "all" ? null : DateTime.UtcNow.AddDays(-int.Parse(WindowValue, CultureInfo.InvariantCulture));
            var ids = new List<long>();
            const int size = 200;
            for (var page = 1; ids.Count < AcknowledgeAllMax; page++)
            {
                var (rows, total, _) = await _store.PageAsync(GridState(page, size, openOnly: true), from, ct);
                ids.AddRange(rows.Where(r => !r.Acknowledged).Select(r => r.Id).Where(id => !ids.Contains(id)));
                if (rows.Count < size || (long)page * size >= total) break;
            }
            if (ids.Count > AcknowledgeAllMax) ids = ids.Take(AcknowledgeAllMax).ToList();
            var done = 0;
            foreach (var id in ids)
                if (await _store.AcknowledgeAsync(id, Me, "acknowledge all: " + why, ct) == "Acknowledged") done++;
            if (SI.Management.Web.Audit.AuditScope.Current is { } a)
            {
                a.Reason = why;
                a.AfterJson = System.Text.Json.JsonSerializer.Serialize(new { acknowledgeAll = true, acknowledged = done, events = ids, window = WindowValue, search = (string?)Request.Query["q"] });
            }
            TempData["toast"] = ids.Count == 0 ? "Nothing to acknowledge: no open event in this filter."
                : $"Acknowledged {GuardReleaseText.Count(done, "open event", "open events")} in this filter. Nothing was released: what is held stays held until a SuperAdmin releases it, or the next complete run replaces it.";
            TempData["toastKind"] = "ok";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            SI.Management.Web.Audit.AuditScope.Current?.Refused(ex.Message);
            TempData["toast"] = "Not acknowledged: " + ex.Message;
            TempData["toastKind"] = "error";
        }
        return Redirect(back);
    }

    /// ?release=&lt;run id&gt; that cannot open a release form says WHY (never silent).
    public string? ReleaseNotice { get; private set; }

    private void CheckReleaseLink()
    {
        if (string.IsNullOrWhiteSpace(ReleaseRun)) return;
        var r = AllReleases.FirstOrDefault(x => string.Equals(x.RunId, ReleaseRun, StringComparison.OrdinalIgnoreCase));
        if (r is null) ReleaseNotice = $"Nothing is held for {ReleaseRun} any more -- it was released, expired, or is older than the held sets this page lists.";
        else if (!r.CanRelease(DateTime.UtcNow))
            ReleaseNotice = r.State == "held" ? "It can no longer be released: a held set can be released for 7 days, and this one has expired."
                : $"It is already {r.State}{(string.IsNullOrEmpty(r.ReleasedBy) ? "" : " by " + r.ReleasedBy)}{(r.ReleasedUtc is { } u ? " " + Fmt.When(u) : "")} -- there is nothing to release.";
        else if (!MayRelease) ReleaseNotice = "Only a SuperAdmin can release a held set or a held collection. You can see what is held and acknowledge the event.";
    }

    /// This page's URL with the current query, some parameters overridden (null removes one; anything but p starts at 1).
    public string Link(params (string Key, string? Value)[] overrides)
    {
        var over = overrides.Select(o => o.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var parts = new List<(string, string)>();
        foreach (var kv in Request.Query)
        {
            if (over.Contains(kv.Key)) continue;
            if (kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase) && overrides.Length > 0) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add((kv.Key, v));
        }
        foreach (var (k, v) in overrides) if (!string.IsNullOrEmpty(v)) parts.Add((k, v));
        var qs = string.Join("&", parts.Select(x => Uri.EscapeDataString(x.Item1) + "=" + Uri.EscapeDataString(x.Item2)));
        return "/Admin/Guards" + (qs.Length > 0 ? "?" + qs : "");
    }
}
