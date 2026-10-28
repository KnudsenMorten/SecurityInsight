using System.Security.Claims;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Links;
using SI.Management.Web.Settings;
using SI.Management.Web.Navigation;

namespace SI.Management.Web.Exemptions;

/// One finding as the request page resolved it (from the findings browser or a collection view). Category = the
/// finding's Category from the Risk Analysis row (#283); null = not known here -- the flow reads it from the Pro data.
public sealed record FindingRef(string FindingId, string AssetKey, string? AssetName, string? ReportName, string? Cve, string? ConfigurationId, string? Domain, string? Title,
    string? Category = null);

/// What the requester filled in: what to exempt, why, for how long, asked of whom, and -- for an approver -- approve now.
/// #391: DepartmentId = the department whose OWN page the request was made on (set by the server from the selection, never
/// from a form field): its business approvers are asked instead of the security owners.
public sealed record RequestForm(string Scope, string Reason, string? Period, DateTime? CustomDate, string? Approver, bool ApproveNow, int? DepartmentId = null);

public sealed record RequestOutcome(IReadOnlyList<RequestRow> Requests, int Items, int Approved, IReadOnlyList<string> Problems, IReadOnlyList<string> Notes)
{
    public bool Ok => Requests.Count > 0;
    /// #391: who the requests were routed to, in words, when they were made on a department's page (null elsewhere).
    public string? RoutedTo { get; init; }
}

/// #391: who a request is asked of -- the people, and the department whose business approvers they are (null = the
/// security domain / category owners).
public sealed record AskedOf(IReadOnlyList<string> People, string? Department);

/// <summary>
/// Who holds which role for which node -- a security domain (level 1) or a category inside it (level 2, #283). A '*'
/// domain-level role holds for every domain. THE resolution of who decides an exemption request:
/// <list type="bullet">
/// <item><see cref="Asked"/> -- the MOST SPECIFIC set, the people the request is routed and mailed to: the category's
/// owners when the category has any, else the domain's owners, else (backwards compatibility) the domain's approvers.</item>
/// <item><see cref="Deciders"/> -- everyone who MAY decide: the category's owners, the domain's owners (a Domain Owner
/// may always decide), and the domain's approvers (the older role, still honoured). An Admin's override is the role
/// framework's, in <c>ExemptionWorkflow.CanDecide</c>.</item>
/// </list>
/// ONE approval is enough.
/// </summary>
/// <summary>
/// #335: the department side of who decides an exemption request -- the department a request was raised from (its
/// governance log) and that department's business approvers. Implemented by the department layer; absent = no department
/// approvals (the domain / category owners and Admins decide, as before).
/// </summary>
public interface IDepartmentDeciders
{
    Task<(int DepartmentId, string Name)?> DepartmentOfRequestAsync(long requestId, CancellationToken ct);
    Task<bool> IsBusinessApproverAsync(ClaimsPrincipal user, int departmentId, CancellationToken ct);
    Task<IReadOnlyList<string>> BusinessApproverMailsAsync(int departmentId, CancellationToken ct);
    /// #391: the department's name and business approvers (names + mail addresses) for routing a request made on its own
    /// page. Null = no such (live) department, or it cannot be read.
    Task<DepartmentApproverSet?> BusinessApproversAsync(int departmentId, CancellationToken ct);
}

public sealed class Roster
{
    public IReadOnlyList<DomainRoleRow> Rows { get; }
    public Roster(IEnumerable<DomainRoleRow> rows) => Rows = rows.ToList();

    private static bool Eq(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static IReadOnlyList<string> People(IEnumerable<DomainRoleRow> rows) => rows.Select(r => r.Principal.ToLowerInvariant()).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();

    private IEnumerable<DomainRoleRow> DomainLevel(string domain, string role) => Rows
        .Where(r => r.Role == role && !r.IsCategory && (Eq(r.Domain, domain) || r.Domain == DomainRoles.AnyDomain));

    /// The Domain Owners of a domain (its own and the '*' owners) -- domain level only.
    public IReadOnlyList<string> Owners(string domain) => People(DomainLevel(domain, DomainRoles.Owner));
    /// The holders of the older approver role for a domain (its own and '*').
    public IReadOnlyList<string> Approvers(string domain) => People(DomainLevel(domain, DomainRoles.Approver));
    /// The Category Owners of one category of one domain (none for a finding without a category).
    public IReadOnlyList<string> CategoryOwners(string domain, string? category)
    {
        var c = DomainRoles.NormalizeCategory(category);
        return c is null ? Array.Empty<string>() : People(Rows.Where(r => r.Role == DomainRoles.Owner && r.IsCategory && Eq(r.Domain, domain) && Eq(r.Category, c)));
    }

    /// The category whose owners decide a finding of (domain, category): the category itself (spelled as the roster
    /// names it) when it has owners, else null (the domain decides). This is how a request is keyed.
    public string? RoutingCategory(string domain, string? category)
    {
        var c = DomainRoles.NormalizeCategory(category);
        return c is null ? null : Rows.FirstOrDefault(r => r.Role == DomainRoles.Owner && r.IsCategory && Eq(r.Domain, domain) && Eq(r.Category, c))?.Category;
    }

    /// The most specific set: category owners, else domain owners, else (compat) the domain's approvers.
    public IReadOnlyList<string> Asked(string domain, string? category)
    {
        var c = CategoryOwners(domain, category);
        if (c.Count > 0) return c;
        var o = Owners(domain);
        return o.Count > 0 ? o : Approvers(domain);
    }

    /// Everyone who may decide (besides an Admin): category owners + domain owners + the domain's approvers.
    public IReadOnlyList<string> Deciders(string domain, string? category) =>
        CategoryOwners(domain, category).Concat(Owners(domain)).Concat(Approvers(domain)).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();

    /// Everyone who reviews an exemption of (domain, category) besides an Admin: its category's owners + the domain's owners.
    public IReadOnlyList<string> Reviewers(string domain, string? category) =>
        CategoryOwners(domain, category).Concat(Owners(domain)).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();

    public bool IsDecider(string user, string domain, string? category) => Deciders(domain, category).Contains(user.ToLowerInvariant());
    public bool IsReviewer(string user, string domain, string? category) => Reviewers(domain, category).Contains(user.ToLowerInvariant());

    public bool IsOwner(string user, string domain) => Owners(domain).Contains(user.ToLowerInvariant());
    public bool IsApprover(string user, string domain) => Approvers(domain).Contains(user.ToLowerInvariant());
    public bool IsAnyApprover(string user) => Rows.Any(r => r.Role == DomainRoles.Approver && Eq(r.Principal, user));
    /// An owner of anything (domain or category level).
    public bool IsAnyOwner(string user) => Rows.Any(r => r.Role == DomainRoles.Owner && Eq(r.Principal, user));
    public IReadOnlyList<string> AllApprovers => People(Rows.Where(r => r.Role == DomainRoles.Approver));
    /// Everyone who decides something: every owner (both levels) and every approver.
    public IReadOnlyList<string> AllDeciders => People(Rows);
    public IReadOnlyList<string> DomainsOf(string user, string role) => Rows.Where(r => r.Role == role && !r.IsCategory && Eq(r.Principal, user)).Select(r => r.Domain).Distinct().ToList();

    /// The nodes a person owns, both levels: (domain, null) or (domain, category).
    public IReadOnlyList<(string Domain, string? Category)> OwnedBy(string user) => Rows
        .Where(r => r.Role == DomainRoles.Owner && Eq(r.Principal, user))
        .Select(r => (r.Domain, r.IsCategory ? r.Category : null)).Distinct().OrderBy(x => x.Domain).ThenBy(x => x.Item2 ?? "").ToList();
}

/// <summary>
/// THE exemption flow (#252): request -> approve / reject -> active -> review (extend / keep / end) or expire.
/// Role gating lives here, not in the pages: anyone with read access (Admin or Viewer) requests; an approver of the
/// request's domain (or an Admin) decides; an owner of the exemption's domain (or an Admin) reviews. Only an approved
/// request writes cfg.Exemption -- the table the engines read. Every step is written with its cfg.ChangeLog row by
/// <see cref="IExemptionStore"/>, and the request / decision mails go to the outbox through <see cref="IExemptionMailer"/>.
/// </summary>
public sealed class ExemptionWorkflow
{
    public const int MaxItems = 2000;
    public const string ActionExtend = "extend";
    public const string ActionKeep = "keep";
    public const string ActionEnd = "end";

    private readonly IExemptionStore _store;
    private readonly ExemptionSettings _settings;
    private readonly IExemptionMailer _mailer;
    private readonly ExemptionRepository _rules;
    private readonly DeepLinks? _links;
    private readonly TimeProvider _clock;
    private readonly ILogger<ExemptionWorkflow> _log;
    private readonly IAccessScope _access;

    public ExemptionWorkflow(IExemptionStore store, ExemptionSettings settings, IExemptionMailer mailer, ExemptionRepository rules, ILogger<ExemptionWorkflow> log,
        DeepLinks? links = null, TimeProvider? clock = null, IAccessScope? access = null, SI.Management.Web.Audit.IChangeAttributionWriter? attribution = null,
        IDepartmentDeciders? departments = null)
    { _store = store; _settings = settings; _mailer = mailer; _rules = rules; _log = log; _links = links; _clock = clock ?? TimeProvider.System; _access = access ?? DefaultAccess; _attribution = attribution; _departments = departments; }

    /// #335: the department's business approvers decide the requests raised from that department's findings.
    private readonly IDepartmentDeciders? _departments;

    /// <summary>
    /// #335: a request raised from a department's governance log ("accept the risk") may ALSO be decided by that
    /// department's business approvers -- a person on the role ladder (Reader and up; never an off-ladder session such as
    /// an advisor's or a magic link's, the same rule as a listed domain approver) who is a business approver of the ONE
    /// department the request was raised from. Fails closed.
    /// </summary>
    /// #391: a request made on a department's own page and routed to its business approvers is decided by THAT
    /// department's business approvers (the department stored on the request -- never one named by a form).
    private async Task<bool> DepartmentDecidesAsync(ClaimsPrincipal user, RequestRow r, CancellationToken ct)
    {
        if (_departments is null) return false;
        try
        {
            int? dept = r.RoutedToDepartment ? r.DepartmentId : (await _departments.DepartmentOfRequestAsync(r.RequestId, ct))?.DepartmentId;
            return dept is { } d && await IsBusinessApproverAsync(user, d, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the department approvers of request {Id} could not be read", r.RequestId);
            return false;
        }
    }

    /// A business approver of the department who is on the role ladder (Reader and up -- never an off-ladder session such
    /// as an advisor's or a magic link's). Fails closed.
    private async Task<bool> IsBusinessApproverAsync(ClaimsPrincipal user, int departmentId, CancellationToken ct)
    {
        if (_departments is null || user.Identity?.IsAuthenticated != true) return false;
        if (RoleDefinitions.RankOf(user.EffectiveRole()) < RoleDefinitions.RankOf(SiRole.Reader)) return false;
        try { return await _departments.IsBusinessApproverAsync(user, departmentId, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the business approvers of department {Id} could not be read", departmentId);
            return false;
        }
    }

    /// <summary>
    /// #391: the business approvers of the department a request is made on (its own page). Null = no department context,
    /// no department layer, or the department cannot be read -- the security owners are asked, as everywhere else.
    /// </summary>
    public async Task<DepartmentApproverSet?> DepartmentRouteAsync(int? departmentId, CancellationToken ct)
    {
        if (departmentId is not > 0 || _departments is null) return null;
        try { return await _departments.BusinessApproversAsync(departmentId.Value, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the business approvers of department {Id} could not be read -- the security owners are asked", departmentId);
            return null;
        }
    }

    /// #391: who a request is asked of -- the business approvers of its department when it was routed there, else the most
    /// specific security owners (the request's own approver, when the requester picked one, is shown by the page itself).
    public async Task<AskedOf> AskedOfAsync(Roster roster, RequestRow r, CancellationToken ct)
    {
        if (r.RoutedToDepartment && await DepartmentRouteAsync(r.DepartmentId, ct) is { } d) return new AskedOf(d.Names, d.Name);
        return new AskedOf(roster.Asked(r.Domain, r.Category), null);
    }

    /// #391: the ids of the waiting requests among <paramref name="requests"/> this user decides as a business approver of
    /// the department they were routed to (one membership read per department).
    public async Task<IReadOnlySet<long>> DecidedAsBusinessApproverAsync(ClaimsPrincipal user, IEnumerable<RequestRow> requests, CancellationToken ct)
    {
        var ids = new HashSet<long>();
        var known = new Dictionary<int, bool>();
        foreach (var r in requests.Where(r => r.State == ExemptionStates.Requested && r.RoutedToDepartment))
        {
            var d = r.DepartmentId!.Value;
            if (!known.TryGetValue(d, out var yes)) known[d] = yes = await IsBusinessApproverAsync(user, d, ct);
            if (yes) ids.Add(r.RequestId);
        }
        return ids;
    }

    /// <summary>
    /// #335: a request raised from a department's log is also put to the department's business approvers (mail, when
    /// exemption mail is on). Best effort: the request stands whether or not the mail can be queued.
    /// </summary>
    public async Task<IReadOnlyList<string>> AskDepartmentAsync(RequestRow r, int departmentId, CancellationToken ct)
    {
        if (_departments is null) return Array.Empty<string>();
        try
        {
            var to = await _departments.BusinessApproverMailsAsync(departmentId, ct);
            if (to.Count == 0) return to;
            var s = await _settings.ReadAsync(ct);
            if (s.MailEnabled)
            {
                var items = await _store.ItemsAsync(r.RequestId, ct);
                var link = await LinkAsync("/Exemptions/Decide", new Dictionary<string, string?> { ["id"] = r.RequestId.ToString(System.Globalization.CultureInfo.InvariantCulture) }, ct);
                await MailAsync(ExemptionMailComposer.Request(r, items, to, link), r.RequestedBy, ct);
            }
            return to;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the department's business approvers could not be asked for request {Id}", r.RequestId);
            return Array.Empty<string>();
        }
    }

    /// #302 (AUDIT-1.1): an approved request is put in force by the jobs at their next run -- recorded at the decision with
    /// the REQUESTER as the one who initiated it and the decider as the approver, keyed by the request (its exemptions carry
    /// its id), so the jobs' audit rows name both.
    private readonly SI.Management.Web.Audit.IChangeAttributionWriter? _attribution;

    private Task AttributeAsync(string target, string initiatedBy, string? approvedBy, string op, string title, CancellationToken ct) =>
        _attribution is null ? Task.CompletedTask : _attribution.RecordAsync(SI.Management.Web.Audit.ChangeAttribution.CorrelationId(),
            [new SI.Management.Web.Audit.AttributionEntry(target, initiatedBy, SI.Management.Web.Audit.AttributionKinds.Change, op) { ApprovedBy = approvedBy, Title = title }], ct);

    public DateTime Now => _clock.GetUtcNow().UtcDateTime;
    public Task<ExemptionSettings.Values> SettingsAsync(CancellationToken ct) => _settings.ReadAsync(ct);
    public Task<bool> ReadyAsync(CancellationToken ct) => _store.ReadyAsync(ct);
    public async Task<Roster> RosterAsync(CancellationToken ct) => new(await _store.RolesAsync(ct));

    /// <summary>
    /// THE two permission checks of the flow -- "may approve in domain X" and "may review in domain X". Every page and
    /// every write goes through these two methods, and both are decided by the role framework (#253,
    /// <see cref="IAccessScope.CanListed"/>): the action Approve / Review on the target "security domain X", where being
    /// listed for the domain (or '*') in cfg.DomainRole counts as a responsibility. So an Admin / SuperAdmin decides
    /// everywhere, a Delegated user scoped to the domain decides there, a listed approver / owner (Reader and up) decides
    /// their domain as before -- and an advisor or a department person (#258), whose scope is a department, never decides
    /// an exemption. The service is stateless; pages that have no instance at hand get the same one.
    /// </summary>
    /// #283: "listed" = one of <see cref="Roster.Deciders"/> for the node -- a Category Owner of the category, a Domain
    /// Owner of the domain (or '*'), or a holder of the older approver role.
    public static bool CanDecide(ClaimsPrincipal user, Roster roster, string domain, string? category, IAccessScope? access = null) =>
        (access ?? DefaultAccess).CanListed(user, AccessAction.Approve, DomainTarget(domain), roster.IsDecider(user.ChangeName(), domain, category)).Allowed;
    /// A domain-level decision (no category): the domain's owners and approvers.
    public static bool CanDecide(ClaimsPrincipal user, Roster roster, string domain, IAccessScope? access = null) => CanDecide(user, roster, domain, (string?)null, access);
    /// The review counterpart of <see cref="CanDecide(ClaimsPrincipal, Roster, string, IAccessScope?)"/>: the owners of
    /// the exemption's category or domain. Same seam.
    public static bool CanReview(ClaimsPrincipal user, Roster roster, string domainKey, string? category, IAccessScope? access = null) =>
        (access ?? DefaultAccess).CanListed(user, AccessAction.Review, DomainTarget(domainKey), roster.IsReviewer(user.ChangeName(), domainKey, category)).Allowed;
    public static bool CanReview(ClaimsPrincipal user, Roster roster, string domainKey, IAccessScope? access = null) => CanReview(user, roster, domainKey, (string?)null, access);

    private static readonly IAccessScope DefaultAccess = new AccessScopeService();
    /// The target of a decision / review: one security domain, every asset kind and tier in it.
    public static ScopeTarget DomainTarget(string domain) => new(domain == DomainRoles.AnyDomain ? null : domain, null, null);

    private async Task<string?> LinkAsync(string page, IReadOnlyDictionary<string, string?> q, CancellationToken ct)
    {
        if (_links is null) return null;
        try { return await _links.DeepAsync(page, q, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "no link for the exemption mail"); return null; }
    }

    private async Task MailAsync(QueuedMail mail, string by, CancellationToken ct)
    {
        if (mail.To.Count == 0) return;
        try { await _mailer.SendAsync(mail, by, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // the decision itself is written; a mail that cannot be queued is logged, never a reason to undo it
            _log.LogError(ex, "queueing the exemption {Kind} mail failed", mail.Kind);
        }
    }

    // ------------------------------------------------------------------------------------------------- request

    /// <summary>
    /// #283: every finding with its Category -- the ones that came without one (a collection grid's row, the findings
    /// browser's list) are read from the Pro data in one bounded query. A finding the data has no category for stays
    /// without one (its domain's owners decide it).
    /// </summary>
    public async Task<IReadOnlyList<FindingRef>> WithCategoriesAsync(IReadOnlyList<FindingRef> findings, CancellationToken ct)
    {
        var missing = findings.Where(f => DomainRoles.NormalizeCategory(f.Category) is null && !string.IsNullOrWhiteSpace(f.FindingId)).Select(f => f.FindingId).Distinct().ToList();
        if (missing.Count == 0) return findings;
        IReadOnlyDictionary<string, string> map;
        try { map = await _store.CategoriesAsync(missing, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // never a reason to refuse a request: without its category a finding is decided by its domain's owners
            _log.LogWarning(ex, "the findings' categories could not be read -- the domain owners decide them");
            return findings;
        }
        return findings.Select(f => DomainRoles.NormalizeCategory(f.Category) is null && map.TryGetValue(f.FindingId, out var c) ? f with { Category = c } : f).ToList();
    }

    /// One request-to-be: the node that decides it, its findings, and exactly who will be asked (#283).
    public sealed record RequestGroup(string Domain, string? Category, int Findings, IReadOnlyList<string> Asked, IReadOnlyList<string> Deciders)
    {
        public string Label => DomainRoles.Label(Domain, Category);
    }

    /// <summary>
    /// How a set of findings is split into requests: one per (security domain, deciding category) -- the category only
    /// when it has its own owners, so a domain whose categories have no owners still gets ONE request. With the most
    /// specific approvers each request is routed to. PURE over the roster.
    /// </summary>
    public static IReadOnlyList<RequestGroup> Groups(Roster roster, IEnumerable<FindingRef> findings) => findings
        .Select(f => (Domain: DomainRoles.Normalize(f.Domain), Category: DomainRoles.NormalizeCategory(f.Category)))
        .Select(x => (x.Domain, Route: roster.RoutingCategory(x.Domain, x.Category)))
        .GroupBy(x => (x.Domain.ToLowerInvariant(), (x.Route ?? "").ToLowerInvariant()))
        .Select(g => new RequestGroup(g.First().Domain, g.First().Route, g.Count(), roster.Asked(g.First().Domain, g.First().Route), roster.Deciders(g.First().Domain, g.First().Route)))
        .OrderBy(g => g.Domain, StringComparer.OrdinalIgnoreCase).ThenBy(g => g.Category ?? "", StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>
    /// #330: the dialog's preview of a selection -- the approvers' names per request, whether this user may approve it all
    /// now, the real alternative approvers and the one wider scope that fits. Reads only. Without the request tables (or
    /// a roster) nobody is named and nothing is offered.
    /// </summary>
    /// #391: <paramref name="departmentId"/> = the department whose own page the selection was made on -- its business
    /// approvers are named (or, when it has none, the owners with a sentence saying so).
    public async Task<ExemptionPreview> PreviewAsync(ClaimsPrincipal user, IReadOnlyList<FindingRef> findings, int alreadyExempted, CancellationToken ct, int? departmentId = null)
    {
        var ready = await _store.ReadyAsync(ct);
        var roster = ready ? new Roster(await _store.RolesAsync(ct)) : new Roster(Array.Empty<DomainRoleRow>());
        findings = await WithCategoriesAsync(findings, ct);
        var dept = ready ? await DepartmentRouteAsync(departmentId, ct) : null;
        var isBa = dept is { Any: true } && await IsBusinessApproverAsync(user, dept.DepartmentId, ct);
        return ExemptionPreview.Build(roster, findings, (d, c) => CanDecide(user, roster, d, c, _access), alreadyExempted, dept, isBa);
    }

    /// <summary>
    /// Requests an exemption of the same reason, period and approver for every finding given (by selection or by
    /// filter). One request per security domain -- or, where a finding's category has its own Category Owners (#283),
    /// per category -- routed to the most specific owners. With ApproveNow, a requester who may decide a request's
    /// scope approves it in the same step (recorded as approved by them); otherwise it waits for a decision.
    /// </summary>
    public async Task<RequestOutcome> RequestAsync(ClaimsPrincipal user, RequestForm form, IReadOnlyList<FindingRef> findings, string source, CancellationToken ct)
    {
        var problems = new List<string>();
        var notes = new List<string>();
        RequestOutcome Fail(params string[] why) => new(Array.Empty<RequestRow>(), 0, 0, why, notes);
        if (!user.IsReader()) return Fail("only an Admin or a Viewer can request an exemption");
        var by = user.ChangeName();
        if (string.IsNullOrWhiteSpace(by)) return Fail("the signed-in user has no name to record");
        if (!await _store.ReadyAsync(ct)) return Fail("this database does not have the exemption request tables yet -- run the Pro settings setup (it only adds)");
        var reason = (form.Reason ?? "").Trim();
        if (reason.Length < 3) return Fail("give a reason (at least 3 characters) -- it is what the approver and the audit see");
        if (reason.Length > 400) return Fail("the reason is longer than 400 characters");
        if (!ExemptionRepository.Scopes.Contains(form.Scope)) return Fail($"'{form.Scope}' is not an exemption scope (finding, issue, asset)");
        if (findings.Count == 0) return Fail("select at least one finding");
        if (findings.Count > MaxItems) return Fail($"at most {SI.Management.Core.ProData.ScoreFormat.Count(MaxItems)} findings in one request -- narrow the filter");
        var s = await _settings.ReadAsync(ct);
        var (expires, perr) = ExemptionPeriods.Resolve(form.Period, form.CustomDate, s, Now);
        if (perr is not null) return Fail(perr);

        var roster = new Roster(await _store.RolesAsync(ct));
        var approver = string.IsNullOrWhiteSpace(form.Approver) ? null : form.Approver.Trim().ToLowerInvariant();
        findings = await WithCategoriesAsync(findings, ct);

        // #391: made on a department's own page -> asked of that department's business approvers; a department without
        // any -> the security owners, as everywhere else (and the requester is told so)
        DepartmentApproverSet? dept = null;
        string? routing = null;
        if (form.DepartmentId is > 0 && _departments is not null)
        {
            dept = await DepartmentRouteAsync(form.DepartmentId, ct);
            if (dept is null) notes.Add("the department's business approvers could not be read -- the security owners decide it");
            else if (!dept.Any) { routing = ExemptionRouting.DepartmentHasNoBusinessApprover; notes.Add($"{dept.Name} has no business approver -- the security owners decide it"); }
            else routing = ExemptionRouting.DepartmentBusinessApprovers;
        }
        var toDept = routing == ExemptionRouting.DepartmentBusinessApprovers;
        var routingNote = routing is null ? null : toDept ? $"the business approvers of {dept!.Name} ({string.Join(", ", dept.Names)})" : ExemptionRouting.Describe(routing, dept!.Name);
        var userIsBa = toDept && await IsBusinessApproverAsync(user, dept!.DepartmentId, ct);
        var cannotStore = false;

        // findings -> items in the exemption's own words, validated by the rules the run applies, one per target; grouped
        // per (domain, deciding category) -- the category only where it has its own owners (#283)
        var groups = new Dictionary<(string Domain, string Route), (string Domain, string? Category, List<RequestItem> Items)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in findings)
        {
            string? N(string? x) => string.IsNullOrWhiteSpace(x) ? null : x.Trim();
            var cve = N(f.Cve);
            var category = DomainRoles.NormalizeCategory(f.Category);
            var item = form.Scope switch
            {
                ExemptionRepository.ScopeAsset => new RequestItem(ExemptionRepository.ScopeAsset, null, null, null, N(f.AssetKey), N(f.AssetName), null, null, category),
                ExemptionRepository.ScopeIssue => new RequestItem(ExemptionRepository.ScopeIssue, N(f.ReportName), cve is null ? N(f.ConfigurationId) : null, cve, null, null, N(f.Title), null, category),
                _ => new RequestItem(ExemptionRepository.ScopeFinding, N(f.ReportName), cve is null ? N(f.ConfigurationId) : null, cve, N(f.AssetKey), N(f.AssetName), N(f.Title), null, category),
            };
            var why = _rules.Validate(new ExemptionRequest(item.Scope, item.ReportName, item.ConfigurationId, item.Cve, item.AssetKey, item.AssetName, reason, expires));
            if (why.Count > 0) { problems.Add($"{f.AssetName ?? f.FindingId}: {string.Join("; ", why)}"); continue; }
            var domain = DomainRoles.Normalize(f.Domain);
            if (!seen.Add(domain + "|" + item.Identity)) continue;
            var route = roster.RoutingCategory(domain, category);
            var key = (domain.ToLowerInvariant(), (route ?? "").ToLowerInvariant());
            if (!groups.TryGetValue(key, out var g)) groups[key] = g = (domain, route, new List<RequestItem>());
            g.Items.Add(item);
        }

        var created = new List<RequestRow>();
        var approvedNow = 0;
        foreach (var (domain, category, items) in groups.Values.OrderBy(g => g.Domain, StringComparer.OrdinalIgnoreCase).ThenBy(g => g.Category ?? "", StringComparer.OrdinalIgnoreCase))
        {
            var label = DomainRoles.Label(domain, category);
            var asked = roster.Asked(domain, category);
            if (approver is not null && !roster.IsDecider(approver, domain, category) && !(toDept && dept!.Mails.Contains(approver, StringComparer.OrdinalIgnoreCase)))
            {
                problems.Add($"{approver} does not decide {label} (not one of its owners or approvers" + (toDept ? $", nor a business approver of {dept!.Name}" : "")
                    + $") -- its {SI.Management.Core.ProData.ScoreFormat.Count(items.Count)} finding(s) were not requested");
                continue;
            }
            var id = await _store.CreateRequestAsync(new NewRequest(domain, reason, expires, approver, source, items, category,
                routing is null ? null : dept!.DepartmentId, routing, routingNote), by, ct);
            var row = await _store.RequestAsync(id, ct) ?? new RequestRow(id, domain, reason, expires, approver, ExemptionStates.Requested, by, Now, null, null, null, items.Count, source, category);
            // #391: the department decides only what the request RECORDS as routed to it -- a database whose setup has not
            // added the routing columns yet keeps the request with the security owners, and says so
            var routed = toDept && row.RoutedToDepartment;
            if (toDept && !routed) cannotStore = true;
            if (routed) asked = dept!.Names;
            if (form.ApproveNow && (CanDecide(user, roster, domain, category, _access) || (routed && userIsBa)))
            {
                var (st, n) = await _store.ApproveAsync(id, by, "approved when requested", ct);
                if (st == WriteStatus.Saved)
                {
                    approvedNow += items.Count; row = row with { State = ExemptionStates.Approved, DecidedBy = by, DecidedAt = Now };
                    await AttributeAsync($"exemption-request/{id}", by, by, SI.Management.Web.Audit.AttributionOps.Set, $"exemption request #{id} ({label}): {items.Count} finding(s), approved when requested", ct);
                }
                created.Add(row);
                continue;
            }
            if (form.ApproveNow) notes.Add(routed ? $"you are not a business approver of {dept!.Name} nor an owner of {label}: its request waits for one"
                : $"you are not an owner or approver of {label}: its request waits for one");
            created.Add(row);
            if (!routed && asked.Count == 0) notes.Add($"{label} has no owner yet -- an Admin can decide request #{id} ({NavModel.PathOf("/Admin/DomainRoles")} sets owners)");
            if (routed && approver is null && dept!.Mails.Count == 0) notes.Add($"no business approver of {dept.Name} has an e-mail address -- they find request #{id} under Exemptions > To decide");
            if (s.MailEnabled)
            {
                // #391: routed to the department = mailed to its business approvers (the people with a mail address)
                var to = approver is not null ? new[] { approver } : routed ? dept!.Mails.ToArray() : asked.ToArray();
                var link = await LinkAsync("/Exemptions/Decide", new Dictionary<string, string?> { ["id"] = id.ToString(System.Globalization.CultureInfo.InvariantCulture) }, ct);
                await MailAsync(ExemptionMailComposer.Request(row, items, to, link), by, ct);
            }
        }
        if (cannotStore) notes.Add($"this database cannot record the department on a request yet (run the Pro settings setup -- it only adds), so the security owners decide it, not the business approvers of {dept!.Name}");
        var routedTo = created.Any(r => r.RoutedToDepartment) ? ExemptionRouting.Describe(ExemptionRouting.DepartmentBusinessApprovers, dept!.Name)
            : routing == ExemptionRouting.DepartmentHasNoBusinessApprover ? ExemptionRouting.Describe(routing, dept!.Name) : null;
        return new RequestOutcome(created, created.Sum(r => r.ItemCount), approvedNow, problems, notes) { RoutedTo = routedTo };
    }

    // ------------------------------------------------------------------------------------------------- decide

    /// Whether this user may decide this request (#283: the owners of its category or domain, its domain's approvers, or an Admin).
    public bool MayDecide(ClaimsPrincipal user, Roster roster, RequestRow r) => CanDecide(user, roster, r.Domain, r.Category, _access);

    /// <see cref="MayDecide"/>, or (#335) a business approver of the department the request was raised from.
    public async Task<bool> MayDecideAsync(ClaimsPrincipal user, Roster roster, RequestRow r, CancellationToken ct) =>
        MayDecide(user, roster, r) || await DepartmentDecidesAsync(user, r, ct);

    /// The refusal for someone outside the request's deciders: who decides it instead.
    public static string NotYoursToDecide(Roster roster, RequestRow r, AskedOf? askedOf = null)
    {
        // #391: a request routed to a department's business approvers says so
        if (askedOf?.Department is { } dn)
            return $"only the business approvers of {dn} or the owners of {r.ScopeLabel} (or an Admin) decide this request" + (askedOf.People.Count > 0 ? $" -- it is asked of {string.Join(", ", askedOf.People)}" : "");
        var asked = roster.Asked(r.Domain, r.Category);
        return $"only the owners of {r.ScopeLabel} (or an Admin) decide this request" + (asked.Count > 0 ? $" -- it is asked of {string.Join(", ", asked)}" : "");
    }

    public async Task<WriteResult> ApproveAsync(ClaimsPrincipal user, long requestId, string? comment, CancellationToken ct) =>
        await DecideAsync(user, requestId, true, comment, ct);

    public async Task<WriteResult> RejectAsync(ClaimsPrincipal user, long requestId, string? comment, CancellationToken ct) =>
        await DecideAsync(user, requestId, false, comment, ct);

    private async Task<WriteResult> DecideAsync(ClaimsPrincipal user, long requestId, bool approve, string? comment, CancellationToken ct)
    {
        var by = user.ChangeName();
        var r = await _store.RequestAsync(requestId, ct);
        if (r is null) return new(WriteStatus.Refused, $"request #{requestId} does not exist");
        var roster = new Roster(await _store.RolesAsync(ct));
        if (!CanDecide(user, roster, r.Domain, r.Category, _access) && !await DepartmentDecidesAsync(user, r, ct)) return new(WriteStatus.Refused, NotYoursToDecide(roster, r, await AskedOfAsync(roster, r, ct)));
        if (r.State != ExemptionStates.Requested) return new(WriteStatus.Stale, $"request #{requestId} is already {r.State} -- nothing was written");
        var c = (comment ?? "").Trim();
        if (c.Length > 400) return new(WriteStatus.Refused, "the comment is longer than 400 characters");
        if (!approve && c.Length < 3) return new(WriteStatus.Refused, "say why it is rejected (at least 3 characters) -- the requester gets the comment");
        if (approve && r.ExpiresAt is { } e && e <= Now) return new(WriteStatus.Refused, "the requested end date has passed -- reject it and ask for a new period");
        int created = 0;
        WriteStatus st;
        // #404 (CONFIG-1.1): the exemptions an approval writes are journaled as initiated by the requester, approved by the decider
        if (approve)
            using (SI.Management.Web.Audit.AuditScope.Current?.Journal("gui", initiatedBy: r.RequestedBy, approvedBy: by))
                (st, created) = await _store.ApproveAsync(requestId, by, c.Length == 0 ? null : c, ct);
        else st = await _store.RejectAsync(requestId, by, c, ct);
        if (st != WriteStatus.Saved) return new(st, $"request #{requestId} was decided by someone else meanwhile -- nothing was written");
        if (approve) await AttributeAsync($"exemption-request/{requestId}", r.RequestedBy, by, SI.Management.Web.Audit.AttributionOps.Set, $"exemption request #{requestId} ({r.ScopeLabel}): {created} exemption(s)", ct);
        var s = await _settings.ReadAsync(ct);
        if (s.MailEnabled && !string.Equals(r.RequestedBy, by, StringComparison.OrdinalIgnoreCase))
        {
            var link = await LinkAsync("/Exemptions", new Dictionary<string, string?> { ["view"] = "mine" }, ct);
            await MailAsync(ExemptionMailComposer.Decision(r, approve ? ExemptionStates.Approved : ExemptionStates.Rejected, by, c, created, link), by, ct);
        }
        return new(WriteStatus.Saved, approve
            ? $"request #{requestId} approved: {created} exemption(s) written" + (created < r.ItemCount ? $", {r.ItemCount - created} already exempted" : "") + " -- they apply from the next run"
            : $"request #{requestId} rejected -- nothing was exempted");
    }

    // ------------------------------------------------------------------------------------------------- review

    /// <summary>
    /// An owner's review of 1..N exemptions: extend (a new period from today), keep (as they are -- reviewed), or end.
    /// Each exemption is checked on its own: the reviewer must own its domain (or be an Admin).
    /// </summary>
    public async Task<WriteResult> ReviewAsync(ClaimsPrincipal user, string action, IReadOnlyCollection<long> ids, string? period, DateTime? customDate, string? reason, CancellationToken ct)
    {
        var by = user.ChangeName();
        if (!user.IsReader()) return new(WriteStatus.Refused, "only an Admin or a Viewer can review exemptions");
        if (action is not (ActionExtend or ActionKeep or ActionEnd)) return new(WriteStatus.Refused, $"'{action}' is not a review action (extend, keep, end)");
        if (ids.Count == 0) return new(WriteStatus.Refused, "select at least one exemption");
        if (ids.Count > MaxItems) return new(WriteStatus.Refused, $"at most {SI.Management.Core.ProData.ScoreFormat.Count(MaxItems)} exemptions at a time");
        var why = (reason ?? "").Trim();
        if (why.Length > 400) return new(WriteStatus.Refused, "the reason is longer than 400 characters");
        if (action == ActionEnd && why.Length < 3) return new(WriteStatus.Refused, "say why they end (at least 3 characters)");
        if (why.Length == 0) why = action == ActionKeep ? "reviewed: still needed" : "reviewed: extended";
        DateTime? expires = null;
        if (action == ActionExtend)
        {
            var (e, err) = ExemptionPeriods.Resolve(period, customDate, await _settings.ReadAsync(ct), Now);
            if (err is not null) return new(WriteStatus.Refused, err);
            expires = e;
        }
        var roster = new Roster(await _store.RolesAsync(ct));
        var all = (await _store.ExemptionsAsync(5000, ct)).ToDictionary(x => x.ExemptionId);
        int done = 0, stale = 0;
        var refused = new List<string>();
        foreach (var id in ids.Distinct())
        {
            if (!all.TryGetValue(id, out var x)) { refused.Add($"#{id}: no such exemption"); continue; }
            if (!CanReview(user, roster, x.DomainKey, x.CategoryKey, _access)) { refused.Add($"#{id}: you are not an owner of {x.ScopeLabel}"); continue; }
            var state = x.State(Now);
            if (state == ExemptionStates.Ended) { stale++; continue; }
            if (action == ActionKeep && state == ExemptionStates.Expired) { refused.Add($"#{id}: it has expired -- extend it to keep it"); continue; }
            var st = action switch
            {
                ActionExtend => await _store.ExtendAsync(id, expires, by, why, ct),
                ActionKeep => await _store.KeepAsync(id, by, why, ct),
                _ => await _store.EndAsync(id, by, why, ct),
            };
            if (st == WriteStatus.Saved)
            {
                done++;
                if (action != ActionKeep) await AttributeAsync($"exemption/{id}", by, null, action == ActionEnd ? SI.Management.Web.Audit.AttributionOps.Remove : SI.Management.Web.Audit.AttributionOps.Set, $"exemption #{id} ({x.ScopeLabel}) {(action == ActionEnd ? "ended" : "extended")} on review", ct);
            }
            else stale++;
        }
        var verb = action switch { ActionExtend => "extended " + ExemptionPeriods.Describe(expires), ActionKeep => "kept", _ => "ended" };
        var msg = $"{SI.Management.Core.ProData.ScoreFormat.Count(done)} exemption(s) {verb}" + (stale > 0 ? $"; {SI.Management.Core.ProData.ScoreFormat.Count(stale)} had already ended" : "") + (refused.Count > 0 ? $"; {SI.Management.Core.ProData.ScoreFormat.Count(refused.Count)} refused: {refused[0]}" : "");
        return new(done > 0 ? WriteStatus.Saved : refused.Count > 0 ? WriteStatus.Refused : WriteStatus.Stale, msg);
    }

    // ------------------------------------------------------------------------------------------------- reading

    public Task<IReadOnlyList<ExemptionInfo>> ExemptionsAsync(CancellationToken ct) => _store.ExemptionsAsync(5000, ct);
    public Task<IReadOnlyList<RequestRow>> RequestsAsync(string? state, CancellationToken ct) => _store.RequestsAsync(state, 500, ct);
    public Task<RequestRow?> RequestAsync(long id, CancellationToken ct) => _store.RequestAsync(id, ct);
    public Task<IReadOnlyList<RequestItem>> ItemsAsync(long id, CancellationToken ct) => _store.ItemsAsync(id, ct);

    // ------------------------------------------------------------------------------------------------- roles (Admin)

    /// The Domain -> Category pairs the data carries (#283), for the Security owners page; empty when they cannot be read.
    public async Task<IReadOnlyList<(string Domain, string Category)>> CategoryPairsAsync(CancellationToken ct)
    {
        try { return await _store.CategoryPairsAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the categories in the data could not be read");
            return Array.Empty<(string, string)>();
        }
    }

    /// Whether the latest collection's pairs are written by the data sync (true), being prepared (false) or the database lacks
    /// the tables (null). Unreadable = true (the page then says nothing extra; the pairs read reports its own failure).
    public async Task<bool?> CategoryPairsWrittenAsync(CancellationToken ct)
    {
        try { return await _store.CategoryPairsWrittenAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "whether the categories in the data are written could not be read");
            return true;
        }
    }

    /// A category name as people enter it: what the reports carry (letters, digits, spaces and the punctuation they use).
    public static bool IsCategoryName(string c) => System.Text.RegularExpressions.Regex.IsMatch(c, @"^[\p{L}\p{N} _\-().,&/:+']{1,128}$");

    /// <summary>
    /// Adds or removes a person: a Domain Owner or approver (category blank) or a Category Owner (#283: domain + category,
    /// owners only, a real domain -- not '*'). Admin only; every change is one transaction with its ChangeLog row.
    /// </summary>
    public async Task<WriteResult> SetRoleAsync(ClaimsPrincipal user, bool add, string domain, string? category, string role, string principal, CancellationToken ct)
    {
        if (!user.IsAdmin()) return new(WriteStatus.Refused, "only an Admin sets security owners and approvers");
        var d = (domain ?? "").Trim();
        if (d != DomainRoles.AnyDomain && !System.Text.RegularExpressions.Regex.IsMatch(d, @"^[A-Za-z0-9 _\-]{1,64}$")) return new(WriteStatus.Refused, $"'{domain}' is not a security domain");
        if (!DomainRoles.All.Contains(role)) return new(WriteStatus.Refused, $"'{role}' is not a role (owner, approver)");
        var c = DomainRoles.NormalizeCategory(category);
        if (c is not null)
        {
            if (d == DomainRoles.AnyDomain) return new(WriteStatus.Refused, "a category belongs to one security domain -- pick the domain, not \"Every domain\"");
            if (role != DomainRoles.Owner) return new(WriteStatus.Refused, "a category has owners only -- its owners approve its requests (the approver role is per domain)");
            if (!IsCategoryName(c)) return new(WriteStatus.Refused, $"'{category}' is not a category name");
        }
        var p = (principal ?? "").Trim().ToLowerInvariant();
        if (!System.Text.RegularExpressions.Regex.IsMatch(p, @"^[^@\s;,<>""']{1,128}@[A-Za-z0-9.\-]{1,120}\.[A-Za-z]{2,}$")) return new(WriteStatus.Refused, $"'{principal}' is not a user principal name / e-mail address");
        if (!await _store.ReadyAsync(ct)) return new(WriteStatus.Refused, "this database does not have the security owner tables yet -- run the Pro settings setup (it only adds)");
        return add ? await _store.AddRoleAsync(d, c, role, p, user.ChangeName(), ct) : await _store.RemoveRoleAsync(d, c, role, p, user.ChangeName(), ct);
    }

    /// The domain-level form (no category) -- unchanged for its callers.
    public Task<WriteResult> SetRoleAsync(ClaimsPrincipal user, bool add, string domain, string role, string principal, CancellationToken ct) =>
        SetRoleAsync(user, add, domain, null, role, principal, ct);
}
