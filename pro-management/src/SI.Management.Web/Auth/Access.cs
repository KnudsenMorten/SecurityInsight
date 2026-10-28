using System.Security.Claims;
using System.Text.Json;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Auth;

/// <summary>
/// The four roles of the web app, the same as PIM Manager's: Reader &lt; Delegated &lt; Admin &lt; SuperAdmin. The
/// EFFECTIVE role is the highest of the Entra app role (which gates sign-in) and the portal mapping (Admin &gt; Access).
/// Wallboard is not on this ladder: it is the kiosk sign-in, which opens the wall board and nothing else.
/// </summary>
public enum SiRole
{
    None = 0,
    /// Every view, export and chat; no changes. The Entra app role value "Viewer" (and "Reader") means Reader.
    Reader = 1,
    /// Admin rights limited to the assigned scopes. Portal only.
    Delegated = 2,
    /// Everything in the install except role management and the install's own lifecycle.
    Admin = 3,
    /// Also role and scope assignment, licence, updates / template releases, support access.
    SuperAdmin = 4,
    /// OFF the ladder (rank 0, #258): an external advisor of a department -- sees that department only and may comment,
    /// recommend and (after a strong sign-in) approve there. Never assigned on Admin &gt; Access: it comes from
    /// cfg.DepartmentAdvisor, signed in by magic link or as an Entra B2B guest. Compare roles by
    /// <see cref="RoleDefinition.Rank"/>, never by this number.
    Advisor = 5,
    /// OFF the ladder (rank 0, #254/#258): a person of a department (technical / business owner, approver, delegate) who
    /// holds no ladder role -- the same rights as an advisor, on their own departments.
    DepartmentMember = 6,
}

/// What a signed-in user asks to do. The delegable ones (Exempt, Override, TierMove, Review) are allowed to a Delegated
/// user inside their scopes; the rest need a role.
public enum AccessAction
{
    /// Open a view, export it, ask the chat. Reader and up.
    View,
    /// Stage, revoke or decide an exemption (#252's approver decision is this action).
    Exempt,
    /// Override a rule (switch a tier rule off).
    Override,
    /// Move an asset (pin) or a whole rule to another tier.
    TierMove,
    /// Review exemptions (the monthly owner review of #252).
    Review,
    /// Comment on a finding / exemption (the exemption flow, and the advisors of #258).
    Comment,
    /// Recommend a decision (advisors, #258).
    Recommend,
    /// Approve or reject a request (the approver of #252). The action a role can demand a strong sign-in for.
    Approve,
    /// Settings, documents, connectors, jobs, template conformance -- the Admin pages. Admin and up.
    Administer,
    /// Role and scope assignment (Admin > Access). SuperAdmin.
    ManageAccess,
    /// The licence (its request settings). SuperAdmin.
    Licence,
    /// Product updates and template releases / roll backs, and the jobs that run them. SuperAdmin.
    Lifecycle,
    /// Granting or revoking the vendor's support access. SuperAdmin.
    SupportAccess,
}

/// <summary>
/// A KIND of scope a Delegated assignment can be limited by. The model is (scope type, scope value) pairs, so a new kind
/// (the department of the asset-responsibility framework, #254) is one more entry in <see cref="ScopeTypes.All"/> -- the
/// callers of <see cref="IAccessScope"/> do not change; the code that knows a target's department sets it on the
/// <see cref="ScopeTarget"/>.
/// </summary>
/// <param name="Id">The stored type name ("domain").</param>
/// <param name="Label">How it reads ("security domain").</param>
/// <param name="Anchor">An assignment must name at least one anchor type (what the person is responsible for).</param>
/// <param name="RestrictsVisibility">The holder SEES only rows inside this type's values (a department); false = sees
/// everything, changes only inside (a security domain).</param>
/// <param name="Column">The key of the finding column in <see cref="VisibilityPredicate.Columns"/>; null = cannot filter.</param>
/// <param name="Wildcard">A value meaning "every value" ("*"), or null.</param>
public sealed record ScopeType(string Id, string Label, bool Anchor, bool RestrictsVisibility, string? Column, string? Wildcard, Func<string, string?> Check);

public static class ScopeTypes
{
    public const string Domain = "domain";
    public const string AssetKind = "assetKind";
    public const string Tier = "tier";

    public static readonly ScopeType DomainType = new(Domain, "security domain", Anchor: true, RestrictsVisibility: false, Column: "domain", Wildcard: "*",
        v => SecurityDomains.IsWellFormed(v) ? null : $"'{v}' is not a security domain name");
    public static readonly ScopeType AssetKindType = new(AssetKind, "asset kind", Anchor: false, RestrictsVisibility: false, Column: "assetKind", Wildcard: null,
        v => SecurityDomains.AssetKinds.Contains(v, StringComparer.OrdinalIgnoreCase) ? null : $"'{v}' is not an asset kind ({string.Join(", ", SecurityDomains.AssetKinds)})");
    public static readonly ScopeType TierType = new(Tier, "tier", Anchor: false, RestrictsVisibility: false, Column: "tier", Wildcard: null,
        v => v is "0" or "1" or "2" or "3" ? null : $"'{v}' is not a tier (0, 1, 2, 3)");

    /// The department of the asset-responsibility framework (#254): an anchor (what the person is responsible for) that
    /// RESTRICTS what its holder sees -- a Delegated user scoped to a department sees only that department's assets and
    /// findings, on every view. The value is the department's id (cfg.Department.DepartmentId).
    public const string Department = SI.Management.Core.ProData.DepartmentScope.ScopeType;
    public static readonly ScopeType DepartmentType = new(Department, "department", Anchor: true, RestrictsVisibility: true,
        Column: SI.Management.Core.ProData.DepartmentScope.VisibilityColumn, Wildcard: null, SI.Management.Core.ProData.DepartmentScope.Check);

    /// Every scope type the app knows.
    public static readonly IReadOnlyList<ScopeType> All = [DomainType, AssetKindType, TierType, DepartmentType];

    public static ScopeType? Find(string? id, IReadOnlyList<ScopeType>? types = null) =>
        (types ?? All).FirstOrDefault(t => string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase));
}

/// One (scope type, scope value) pair.
public sealed record ScopeEntry(string Type, string Value);

/// <summary>
/// What a Delegated assignment may change: a set of (scope type, value) pairs. Within one type the values are
/// alternatives (Identity OR Azure); across types they narrow each other (Identity AND Tier 2). A type the scope does not
/// name is not constrained.
/// </summary>
public sealed record AccessScope
{
    public const string AnyDomain = "*";
    public IReadOnlyList<ScopeEntry> Entries { get; init; } = Array.Empty<ScopeEntry>();

    public AccessScope() { }
    public AccessScope(IEnumerable<ScopeEntry> entries) =>
        Entries = entries.Where(e => !string.IsNullOrWhiteSpace(e.Type) && !string.IsNullOrWhiteSpace(e.Value))
            .Select(e => new ScopeEntry(ScopeTypes.Find(e.Type)?.Id ?? e.Type.Trim(), e.Value.Trim()))
            .DistinctBy(e => (e.Type.ToLowerInvariant(), e.Value.ToLowerInvariant())).ToList();

    /// Convenience for the three types built today.
    public static AccessScope Of(IEnumerable<string>? domains, IEnumerable<string>? assetKinds = null, IEnumerable<string>? tiers = null) => new(
        (domains ?? []).Select(v => new ScopeEntry(ScopeTypes.Domain, v))
        .Concat((assetKinds ?? []).Select(v => new ScopeEntry(ScopeTypes.AssetKind, v)))
        .Concat((tiers ?? []).Select(v => new ScopeEntry(ScopeTypes.Tier, v))));

    public IReadOnlyList<string> ValuesOf(string type) => Entries.Where(e => string.Equals(e.Type, type, StringComparison.OrdinalIgnoreCase)).Select(e => e.Value).ToList();
    public IReadOnlyList<string> Types => Entries.Select(e => e.Type).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    public IReadOnlyList<string> Domains => ValuesOf(ScopeTypes.Domain);
    public IReadOnlyList<string> AssetKinds => ValuesOf(ScopeTypes.AssetKind);
    public IReadOnlyList<string> Tiers => ValuesOf(ScopeTypes.Tier);
    public bool AllDomains => Domains.Any(d => d == AnyDomain);
    public bool IsEmpty => Entries.Count == 0;

    public string ToJson() => JsonSerializer.Serialize(new { entries = Entries.Select(e => new { type = e.Type, value = e.Value }) });

    /// The stored / claim form back; anything unreadable is the EMPTY scope (which allows nothing).
    public static AccessScope Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new AccessScope();
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Object || !d.RootElement.TryGetProperty("entries", out var a) || a.ValueKind != JsonValueKind.Array) return new AccessScope();
            return new AccessScope(a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object)
                .Select(x => new ScopeEntry(x.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "", x.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "")));
        }
        catch (JsonException) { return new AccessScope(); }
    }

    /// "Identity, Azure" / "Endpoint (asset kind endpoint; tier 2, 3)" / "every domain".
    public string Describe()
    {
        if (IsEmpty) return "no scope";
        var anchors = Entries.Where(e => ScopeTypes.Find(e.Type)?.Anchor == true).GroupBy(e => e.Type, StringComparer.OrdinalIgnoreCase)
            .Select(g => string.Join(", ", g.Select(e => e.Value == AnyDomain ? "every domain" : e.Value)));
        var narrow = Entries.Where(e => ScopeTypes.Find(e.Type)?.Anchor != true).GroupBy(e => e.Type, StringComparer.OrdinalIgnoreCase)
            .Select(g => (ScopeTypes.Find(g.Key)?.Label ?? g.Key) + " " + string.Join(", ", g.Select(e => e.Value))).ToList();
        var s = string.Join("; ", anchors);
        return narrow.Count == 0 ? s : $"{s} ({string.Join("; ", narrow)})";
    }

    /// Why this scope cannot be stored (empty = it can).
    public IReadOnlyList<string> Validate(IReadOnlyList<ScopeType>? types = null)
    {
        var why = new List<string>();
        var known = types ?? ScopeTypes.All;
        if (!Entries.Any(e => ScopeTypes.Find(e.Type, known)?.Anchor == true))
            why.Add($"a Delegated assignment needs at least one {string.Join(" or ", known.Where(t => t.Anchor).Select(t => t.Label))}");
        foreach (var e in Entries)
        {
            var t = ScopeTypes.Find(e.Type, known);
            if (t is null) { why.Add($"'{e.Type}' is not a scope type ({string.Join(", ", known.Select(k => k.Id))})"); continue; }
            if (e.Value == t.Wildcard) continue;
            if (t.Check(e.Value) is { } bad) why.Add(bad);
        }
        return why;
    }

    /// Whether this scope covers the target: for every type the scope names, the target's value of that type must be one
    /// of the scope's values (or the type's wildcard). A target with no value for a named type spans every value of it,
    /// which a narrowed scope never covers. Several assignments add up as ANY (kept apart, never merged).
    public bool Covers(ScopeTarget target, out string why, IReadOnlyList<ScopeType>? types = null)
    {
        why = "";
        if (IsEmpty) { why = "no scope is assigned"; return false; }
        foreach (var g in Entries.GroupBy(e => e.Type, StringComparer.OrdinalIgnoreCase))
        {
            var t = ScopeTypes.Find(g.Key, types);
            var values = g.Select(e => e.Value).ToList();
            if (t?.Wildcard is { } w && values.Contains(w)) continue;
            var label = t?.Label ?? g.Key;
            var v = target.ValueOf(g.Key);
            if (v is null) { why = $"it spans every {label}"; return false; }
            if (!values.Contains(v, StringComparer.OrdinalIgnoreCase)) { why = $"{label} {v} is outside your scope"; return false; }
        }
        return true;
    }
}

/// <summary>
/// What a change touches, for the scope check: a value per scope type. A missing / null value means "every": an issue
/// exemption has no asset kind (it applies to every asset); a shared tier rule has no domain. A scope that names values
/// of a type never covers an "every" of that type.
/// </summary>
public sealed record ScopeTarget
{
    public IReadOnlyDictionary<string, string?> Values { get; }

    public ScopeTarget(IReadOnlyDictionary<string, string?> values) =>
        Values = new Dictionary<string, string?>(values, StringComparer.OrdinalIgnoreCase);

    public ScopeTarget(string? domain, string? assetKind, string? tier) : this(new Dictionary<string, string?>
    {
        [ScopeTypes.Domain] = domain, [ScopeTypes.AssetKind] = assetKind, [ScopeTypes.Tier] = tier,
    }) { }

    public string? ValueOf(string type) => Values.TryGetValue(type, out var v) ? SecurityDomains.Blank(v) : null;
    public string? Domain => ValueOf(ScopeTypes.Domain);
    public string? AssetKind => ValueOf(ScopeTypes.AssetKind);
    public string? Tier => ValueOf(ScopeTypes.Tier);

    /// The same target with one more scope type's value (e.g. the asset's department, #254).
    public ScopeTarget With(string type, string? value)
    {
        var d = new Dictionary<string, string?>(Values, StringComparer.OrdinalIgnoreCase) { [type] = value };
        return new ScopeTarget(d);
    }

    public override string ToString() =>
        $"{Domain ?? "every domain"}" + (AssetKind is null ? "" : " / " + AssetKind) + (Tier is null ? "" : " / Tier " + Tier)
        + string.Concat(Values.Where(kv => kv.Key is not (ScopeTypes.Domain or ScopeTypes.AssetKind or ScopeTypes.Tier) && kv.Value is not null).Select(kv => $" / {kv.Key} {kv.Value}"));
}

/// The security domains and asset kinds, and how the parts of SecurityInsight map onto them.
public static class SecurityDomains
{
    /// The domains of the four asset engines, plus the cross-engine reports. Any other domain present in the data can be
    /// assigned too (the Access page offers the data's values).
    public static readonly IReadOnlyList<string> Known = ["Endpoint", "Identity", "Azure", "PublicIP", "CrossEngine"];
    public static readonly IReadOnlyList<string> AssetKinds = ["endpoint", "identity", "azure", "publicip"];

    public static bool IsWellFormed(string d) => d.Length is > 0 and <= 64 && d.All(c => char.IsLetterOrDigit(c) || c is ' ' or '-' or '_' or '/' or '.');

    /// The domain an asset belongs to, by its kind (endpoint -> Endpoint, ...). Unknown kind -> null (every domain).
    public static string? OfAssetKind(string? kind) => (kind ?? "").Trim().ToLowerInvariant() switch
    {
        "endpoint" => "Endpoint",
        "identity" => "Identity",
        "azure" => "Azure",
        "publicip" => "PublicIP",
        _ => null,
    };

    /// A tier rule key '&lt;engine&gt;/&lt;rule id&gt;': the engine's assets ("shared" rules apply to every engine -> every domain).
    public static ScopeTarget OfRuleKey(string? ruleKey)
    {
        var engine = (ruleKey ?? "").Split('/')[0].Trim().ToLowerInvariant();
        var domain = OfAssetKind(engine);
        return new ScopeTarget(domain, domain is null ? null : engine, null);
    }

    public static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}

/// What belongs to the install's own lifecycle (SuperAdmin): the jobs that update the product and release templates, and
/// the licence settings.
public static class AccessLifecycle
{
    /// Today's names. CR5 step 1: the install's own names (Jobs__UpdaterJob / Jobs__TemplatesJob) count TOO -- a configured
    /// name only ever adds to this list, so a renamed job never loses its SuperAdmin-only guard.
    public static readonly IReadOnlyList<string> Jobs = ["caj-si-updater", "caj-si-templates"];
    public const string LicenceSettingPrefix = "SI_LicenseRequest_";

    public static bool IsLifecycleJob(string? job, SI.Management.Web.Jobs.JobsOptions? options = null)
    {
        var j = (job ?? "").Trim();
        if (j.Length == 0) return false;
        if (Jobs.Contains(j, StringComparer.OrdinalIgnoreCase)) return true;
        if (options is null) return false;
        return string.Equals(j, options.UpdaterJobName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(j, (options.TemplatesJob ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
    }
    public static bool IsLicenceSetting(string? name) => (name ?? "").StartsWith(LicenceSettingPrefix, StringComparison.OrdinalIgnoreCase);
}

/// The answer of a check: allowed, or refused with the reason a person can act on.
public sealed record AccessDecision(bool Allowed, string Reason)
{
    public static readonly AccessDecision Yes = new(true, "");
    public static AccessDecision No(string reason) => new(false, reason);
}

/// <summary>
/// THE one place the web app decides "may this user do this, here" and "what may this user see". Pages, the commit path
/// and the exemption flow (#252: a domain's approver is a Delegated user for that domain, or an Admin) all ask it;
/// nothing else holds a permission rule. It reads only the signed-in user's claims (the effective role and scopes the
/// sign-in resolved).
/// </summary>
public interface IAccessScope
{
    /// May the user do this action on this target (null = no target: a role-only action)?
    AccessDecision Can(ClaimsPrincipal user, AccessAction action, ScopeTarget? target = null);

    /// A bulk action: allowed only when EVERY target is allowed; otherwise refused as a whole, naming the first refusal
    /// and how many are out of scope.
    AccessDecision CanAll(ClaimsPrincipal user, AccessAction action, IReadOnlyCollection<ScopeTarget> targets);

    /// The rows this user may SEE, for the data queries; null = everything (every role, and a Delegated user unless every
    /// one of their scopes is of a type that restricts visibility, e.g. a department).
    VisibilityPredicate? Visibility(ClaimsPrincipal user);

    /// <summary>
    /// <see cref="Can"/>, for an action a RESPONSIBILITY LIST may also grant: the domain approvers / owners of the exemption
    /// flow (#252, cfg.DomainRole) are people named for a target outside the role mapping. <paramref name="listed"/> says
    /// the user is named for this target. The answer: the role framework's own answer when it allows; else, when listed, a
    /// user on the role ladder (Reader and up -- never a magic-link or advisor session) is allowed, under the same
    /// strong-sign-in rule as their role. One place decides both.
    /// </summary>
    AccessDecision CanListed(ClaimsPrincipal user, AccessAction action, ScopeTarget target, bool listed);
}

/// <summary>
/// HOW the signed-in user signed in -- the claim <see cref="Claim"/> on the access identity: "oauth" (Entra, members and
/// B2B guests alike), "magiclink" (a redeemed magic link), "magiclink+otp" (a magic link confirmed with a one-time code
/// mailed to the same mailbox). A role can demand a STRONG sign-in (oauth or magiclink+otp) for an action
/// (<see cref="RoleDefinition.StrongAuth"/>): the Advisor and Department roles of #258 demand it for Approve; the ladder
/// roles demand it for nothing.
/// </summary>
public static class AuthMethods
{
    public const string Claim = "si_auth_method";
    public const string OAuth = "oauth";
    public const string MagicLink = "magiclink";
    public const string MagicLinkOtp = "magiclink+otp";
    /// Set by the one-time-code step (#258) on the magic-link session it confirmed.
    public const string OtpClaim = "si_otp";

    /// What the session is: a magic-link session (the role it carries) is "magiclink", or "magiclink+otp" once its code
    /// was confirmed; every other sign-in is "oauth".
    public static string Detect(ClaimsPrincipal user)
    {
        if (!user.IsInRole(Roles.MagicLink)) return OAuth;
        return string.Equals(user.FindFirst(OtpClaim)?.Value, "true", StringComparison.OrdinalIgnoreCase) ? MagicLinkOtp : MagicLink;
    }

    /// The method the sign-in resolved (the access identity), else detected from the session itself.
    public static string Of(ClaimsPrincipal user) =>
        user.Identities.Where(i => i.AuthenticationType == AccessClaims.IdentityType).SelectMany(i => i.FindAll(Claim)).FirstOrDefault()?.Value ?? Detect(user);

    public static bool IsStrong(string method) => method is OAuth or MagicLinkOtp;
    public static bool IsStrong(ClaimsPrincipal user) => IsStrong(Of(user));
}

/// <summary>
/// One role, as data: its rank on the ladder, the actions it may take, whether those actions are bound to its scopes, and
/// which of them need a strong sign-in. A new role (the external Advisor of #258: Review / Comment / Recommend / Approve on
/// a department scope, Approve only after a strong sign-in) is one more row in <see cref="RoleDefinitions.All"/> -- every
/// caller keeps asking <see cref="IAccessScope.Can"/>.
/// </summary>
public sealed record RoleDefinition(SiRole Role, string Name, int Rank, bool ScopeBound, IReadOnlySet<AccessAction> Actions, IReadOnlySet<AccessAction> StrongAuth)
{
    public bool Allows(AccessAction a) => Actions.Contains(a);
}

public static class RoleDefinitions
{
    private static HashSet<AccessAction> Set(params AccessAction[] a) => new(a);
    private static readonly HashSet<AccessAction> None = new();
    public static readonly IReadOnlySet<AccessAction> Scoped = Set(AccessAction.Exempt, AccessAction.Override, AccessAction.TierMove, AccessAction.Review,
        AccessAction.Comment, AccessAction.Recommend, AccessAction.Approve);
    private static readonly HashSet<AccessAction> Lifecycle = Set(AccessAction.ManageAccess, AccessAction.Licence, AccessAction.Lifecycle, AccessAction.SupportAccess);

    public static readonly IReadOnlyList<RoleDefinition> All =
    [
        new(SiRole.Reader, "Reader", 1, ScopeBound: false, Set(AccessAction.View), None),
        new(SiRole.Delegated, "Delegated", 2, ScopeBound: true, Set([AccessAction.View, .. Scoped]), None),
        new(SiRole.Admin, "Admin", 3, ScopeBound: false, Enum.GetValues<AccessAction>().Where(a => !Lifecycle.Contains(a)).ToHashSet(), None),
        new(SiRole.SuperAdmin, "SuperAdmin", 4, ScopeBound: false, Enum.GetValues<AccessAction>().ToHashSet(), None),
        // #258 (operator decision 2026-10-04): view, comment, recommend on their department; APPROVE only after a strong
        // sign-in (Entra -- a B2B guest -- or a magic link confirmed with the one-time code mailed to the same mailbox).
        // Rank 0: off the ladder, so IsReader / MayChange / IsAdmin never hold for them.
        new(SiRole.Advisor, "Advisor", 0, ScopeBound: true, Set(AccessAction.View, AccessAction.Comment, AccessAction.Recommend, AccessAction.Approve), Set(AccessAction.Approve)),
        new(SiRole.DepartmentMember, "Department", 0, ScopeBound: true, Set(AccessAction.View, AccessAction.Comment, AccessAction.Recommend, AccessAction.Approve), Set(AccessAction.Approve)),
    ];

    /// The ladder roles (rank &gt; 0): the only ones Admin &gt; Access assigns.
    public static IEnumerable<RoleDefinition> Ladder => All.Where(d => d.Rank > 0);

    /// The rank of a role (0 for None and every off-ladder role).
    public static int RankOf(SiRole r) => Find(r)?.Rank ?? 0;

    public static RoleDefinition? Find(SiRole r, IReadOnlyList<RoleDefinition>? defs = null) => (defs ?? All).FirstOrDefault(d => d.Role == r);
    public static RoleDefinition? Find(string? name, IReadOnlyList<RoleDefinition>? defs = null) =>
        (defs ?? All).FirstOrDefault(d => string.Equals(d.Name, name?.Trim(), StringComparison.OrdinalIgnoreCase));
}

public sealed class AccessScopeService : IAccessScope
{
    private readonly IReadOnlyList<ScopeType> _types;
    private readonly IReadOnlyList<RoleDefinition> _roles;
    public AccessScopeService() : this(ScopeTypes.All) { }
    /// Tests (and a later scope type / role) pass their own lists.
    public AccessScopeService(IReadOnlyList<ScopeType> types, IReadOnlyList<RoleDefinition>? roles = null) { _types = types; _roles = roles ?? RoleDefinitions.All; }

    public static bool IsDelegable(AccessAction a) => RoleDefinitions.Scoped.Contains(a);

    /// The lowest role that may take an action at all (for the message).
    public static SiRole Needs(AccessAction a) => RoleDefinitions.Ladder.Where(d => d.Allows(a)).OrderBy(d => d.Rank).Select(d => d.Role).FirstOrDefault(SiRole.SuperAdmin);

    public static string Words(AccessAction a) => a switch
    {
        AccessAction.View => "open this view",
        AccessAction.Exempt => "change exemptions",
        AccessAction.Override => "override rules",
        AccessAction.TierMove => "move tiers",
        AccessAction.Review => "review exemptions",
        AccessAction.Comment => "comment",
        AccessAction.Recommend => "recommend",
        AccessAction.Approve => "approve",
        AccessAction.Administer => "change the install's settings",
        AccessAction.ManageAccess => "assign roles and scopes",
        AccessAction.Licence => "change the licence",
        AccessAction.Lifecycle => "run updates and template releases",
        AccessAction.SupportAccess => "grant support access",
        _ => a.ToString(),
    };

    /// Refuses the action when the user's role demands a strong sign-in for it (oauth, or a magic link confirmed with a
    /// one-time code) and this session is not one. Only the off-ladder roles of #258 demand it (for Approve); the ladder
    /// roles always get Yes.
    public AccessDecision RequireStrongAuthFor(ClaimsPrincipal user, AccessAction action)
    {
        var def = RoleDefinitions.Find(user.EffectiveRole(), _roles);
        if (def is null || !def.StrongAuth.Contains(action) || AuthMethods.IsStrong(user)) return AccessDecision.Yes;
        return AccessDecision.No($"to {Words(action)} you need to sign in with your organisation account, or confirm this link with the one-time code mailed to you (signed in by {AuthMethods.Of(user)})");
    }

    public AccessDecision Can(ClaimsPrincipal user, AccessAction action, ScopeTarget? target = null)
    {
        if (target is not null) NoteTarget(target);
        return Decide(user, action, target);
    }

    /// The audit trail (#260): the target a request is checked against is the target it acts on -- its domain and
    /// department go onto the request's audit row, which is what a Delegated user's view of the trail filters by.
    private static void NoteTarget(ScopeTarget t) =>
        SI.Management.Web.Audit.AuditScope.Current?.NoteTarget(t.Domain,
            int.TryParse(t.ValueOf(ScopeTypes.Department), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : null);

    private AccessDecision Decide(ClaimsPrincipal user, AccessAction action, ScopeTarget? target)
    {
        var role = user.EffectiveRole();
        var def = RoleDefinitions.Find(role, _roles);
        if (def is null || !def.Allows(action))
            return AccessDecision.No($"your role ({AccessClaims.Label(role)}) cannot {Words(action)} -- that needs {AccessClaims.Label(Needs(action))}");
        var strong = RequireStrongAuthFor(user, action);
        if (!strong.Allowed) return strong;
        if (!def.ScopeBound || !IsDelegable(action)) return AccessDecision.Yes;
        // a scope-bound role (Delegated): inside the assigned scopes only
        if (target is null) return AccessDecision.No($"a {def.Name} user can {Words(action)} only on something inside their scopes");
        var scopes = user.Scopes();
        var why = "no scope is assigned";
        foreach (var s in scopes) if (s.Covers(target, out var w, _types)) return AccessDecision.Yes; else why = w;
        return AccessDecision.No($"{target} is outside your scope ({string.Join(" | ", scopes.Select(s => s.Describe()))}): {why}");
    }

    public AccessDecision CanListed(ClaimsPrincipal user, AccessAction action, ScopeTarget target, bool listed)
    {
        var own = Can(user, action, target);
        if (own.Allowed || !listed) return own;
        // listed for the target: a person on the ladder (a Reader named as the domain's approver) -- never an off-ladder
        // session (advisor, department person, magic link), whose name could appear on a list by mail address
        if (RoleDefinitions.RankOf(user.EffectiveRole()) < RoleDefinitions.RankOf(SiRole.Reader)) return own;
        var strong = RequireStrongAuthFor(user, action);
        return strong.Allowed ? AccessDecision.Yes : strong;
    }

    public AccessDecision CanAll(ClaimsPrincipal user, AccessAction action, IReadOnlyCollection<ScopeTarget> targets)
    {
        if (targets.Count == 0) return Can(user, action, null);
        // one domain / department across the whole selection is noted; a selection spanning several is not narrowed to one
        if (targets.Select(t => t.Domain).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1 && targets.Select(t => t.ValueOf(ScopeTypes.Department)).Distinct().Count() == 1)
            NoteTarget(targets.First());
        var refused = targets.Select(t => (t, d: Decide(user, action, t))).Where(x => !x.d.Allowed).ToList();
        if (refused.Count == 0) return AccessDecision.Yes;
        return AccessDecision.No(refused.Count == 1 && targets.Count == 1
            ? refused[0].d.Reason
            : $"{refused.Count} of the {targets.Count} selected are outside your access, so nothing was done. First: {refused[0].d.Reason}");
    }

    public VisibilityPredicate? Visibility(ClaimsPrincipal user)
    {
        if (RoleDefinitions.Find(user.EffectiveRole(), _roles) is not { ScopeBound: true }) return null;
        var scopes = user.Scopes();
        // a scope with no visibility-restricting entry sees everything -> the user does
        var restricting = scopes.Select(s => s.Entries.Where(e => ScopeTypes.Find(e.Type, _types) is { RestrictsVisibility: true, Column: not null }).ToList()).ToList();
        if (restricting.Count == 0 || restricting.Any(r => r.Count == 0)) return null;
        // a restricted scope is filtered by ALL its own columns (its restricting entries and the narrowing ones), so a
        // department scope narrowed to Tier 0 sees that department's Tier 0
        return VisibilityPredicate.Build(scopes.Select(s => (IReadOnlyList<(string, IReadOnlyList<string>)>)s.Entries
            .Select(e => (e, t: ScopeTypes.Find(e.Type, _types)))
            .Where(x => x.t?.Column is not null && x.e.Value != x.t.Wildcard)
            .GroupBy(x => x.t!.Column!, StringComparer.Ordinal)
            .Select(g => (g.Key, (IReadOnlyList<string>)g.Select(x => x.e.Value).ToList())).ToList()).ToList());
    }
}
