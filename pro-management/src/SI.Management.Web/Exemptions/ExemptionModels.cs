namespace SI.Management.Web.Exemptions;

/// <summary>
/// The words of the governed exemption flow (#252). A REQUEST is requested, then approved or rejected by an approver of
/// its security domain; an approved request's findings become EXEMPTIONS (cfg.Exemption, the table the engines read),
/// which are active until they expire (their end date passes) or are ended (an owner or Admin ends them).
/// </summary>
public static class ExemptionStates
{
    public const string Requested = "requested";
    public const string Approved = "approved";
    public const string Rejected = "rejected";
    public const string Active = "active";
    public const string Expired = "expired";
    public const string Ended = "ended";
    public static readonly IReadOnlyList<string> RequestStates = [Requested, Approved, Rejected];
    public static readonly IReadOnlyList<string> ExemptionStatesList = [Active, Expired, Ended];
}

/// <summary>
/// The roles a person can hold, and the domain that means "every domain". #283: two levels of OWNER -- a Security Domain
/// Owner (level 1: the finding's SecurityDomain, e.g. Identity) and a Security Category Owner (level 2: the finding's
/// Category inside that domain, exactly as the Risk Analysis reports carry it, e.g. Identity / Authentication). Owners
/// at both levels decide the exemption requests of their scope and receive the monthly review. The older separate
/// <see cref="Approver"/> role (domain level) still decides, for backwards compatibility.
/// </summary>
public static class DomainRoles
{
    /// Accountable: decides the requests of its scope (#283), receives the monthly review and the expiry warnings, and
    /// reviews (extend / end / keep). At domain level (Category null) or at category level (Category set).
    public const string Owner = "owner";
    /// Decides requests (approve / reject, with a comment). Domain level only; kept for backwards compatibility --
    /// owners decide without it.
    public const string Approver = "approver";
    public static readonly IReadOnlyList<string> All = [Owner, Approver];
    /// A role for EVERY domain (also the home of exemptions made before domains existed).
    public const string AnyDomain = "*";
    /// The security domains SecurityInsight ships; the domains present in the data are added to them.
    public static readonly IReadOnlyList<string> Known = ["Endpoint", "Identity", "Azure", "PublicIP"];
    /// The domain a finding without one is filed under.
    public const string NoDomain = "Other";

    public static string Normalize(string? domain)
    {
        var d = (domain ?? "").Trim();
        return d.Length == 0 ? NoDomain : d.Length > 64 ? d[..64] : d;
    }

    public static string Label(string domain) => domain == AnyDomain ? "Every domain" : domain;

    /// A finding's category as the roster keys it: trimmed, at most 128 characters; blank = none (domain level).
    public static string? NormalizeCategory(string? category)
    {
        var c = (category ?? "").Trim();
        return c.Length == 0 ? null : c.Length > 128 ? c[..128] : c;
    }

    /// "Identity" for a domain node, "Identity / Authentication" for a category node.
    public static string Label(string domain, string? category) => category is null ? Label(domain) : $"{Label(domain)} / {category}";

    /// The role as people read it: Domain Owner, Category Owner, Approver.
    public static string RoleLabel(string role, string? category) => role == Owner ? (category is null ? "Domain Owner" : "Category Owner") : "Approver";
}

/// One person in one role for one node: a security domain (Category null) or a category inside it (#283).
public sealed record DomainRoleRow(string Domain, string Role, string Principal, DateTime? AddedAt, string? AddedBy, string? Category = null)
{
    public bool IsCategory => !string.IsNullOrEmpty(Category);
}

/// One finding (or issue, or asset) of a request, in the exemption's own words.
public sealed record RequestItem(string Scope, string? ReportName, string? ConfigurationId, string? Cve, string? AssetKey, string? AssetName, string? Title,
    long? ExemptionId = null, string? Category = null)
{
    /// Two items that would write the same cfg.Exemption row.
    public string Identity => string.Join("|", Scope, ReportName ?? "", ConfigurationId ?? "", Cve ?? "", AssetKey ?? "").ToLowerInvariant();

    public string Describe() => Scope switch
    {
        "asset" => $"every finding on {AssetName ?? AssetKey}",
        "issue" => $"{Cve ?? ConfigurationId} on every asset" + (ReportName is null ? "" : $" ({ReportName})"),
        _ => $"{Cve ?? ConfigurationId} on {AssetName ?? AssetKey}" + (ReportName is null ? "" : $" ({ReportName})"),
    };
}

/// A request as it is written: one domain, one reason, one end date, one (optional) approver, 1..N items. Category = the
/// category whose owners decide it (#283) -- null when the domain's owners (or approvers) decide it. #391: DepartmentId +
/// Routing = the department page it was requested on and who it was routed to (<see cref="ExemptionRouting"/>);
/// RoutingNote = the same in words, for the change log. All null for a request made anywhere else.
public sealed record NewRequest(string Domain, string Reason, DateTime? ExpiresAt, string? Approver, string Source, IReadOnlyList<RequestItem> Items,
    string? Category = null, int? DepartmentId = null, string? Routing = null, string? RoutingNote = null);

public sealed record RequestRow(long RequestId, string Domain, string Reason, DateTime? ExpiresAt, string? Approver, string State, string RequestedBy,
    DateTime RequestedAt, string? DecidedBy, DateTime? DecidedAt, string? DecisionComment, int ItemCount, string? Source, string? Category = null,
    int? DepartmentId = null, string? Routing = null)
{
    /// "Identity" or "Identity / Authentication": the node whose owners decide it.
    public string ScopeLabel => DomainRoles.Label(Domain, DomainRoles.NormalizeCategory(Category));

    /// #391: requested on a department's page AND routed to that department's business approvers -- the one case in which
    /// they decide a request raised from the action bar.
    public bool RoutedToDepartment => DepartmentId is > 0 && Routing == ExemptionRouting.DepartmentBusinessApprovers;
}

/// <summary>
/// #391: who an exemption request was routed to when it was requested on a department's own page (Departments > a
/// department's findings): that department's BUSINESS APPROVERS -- or, when the department has none, the security domain /
/// category owners as everywhere else. Stored on the request (cfg.ExemptionRequest.DepartmentId + Routing) for the audit;
/// NULL for a request made anywhere else.
/// </summary>
public static class ExemptionRouting
{
    /// Asked of (and decided by) the department's business approvers.
    public const string DepartmentBusinessApprovers = "department-business-approver";
    /// Requested on a department's page, but the department has no business approver: the domain / category owners decide.
    public const string DepartmentHasNoBusinessApprover = "department-no-business-approver";

    /// The routing as people read it.
    public static string Describe(string? routing, string? department) => routing switch
    {
        DepartmentBusinessApprovers => $"the business approvers of {department ?? "the department"} (requested on its page)",
        DepartmentHasNoBusinessApprover => $"the security owners ({department ?? "the department"} has no business approver)",
        _ => "the security owners",
    };
}

/// #391: a department's business approvers as the exemption flow reads them: the names shown (mail address, else display
/// name) and the mail addresses asked. Empty = the department has none.
public sealed record DepartmentApproverSet(int DepartmentId, string Name, IReadOnlyList<string> Names, IReadOnlyList<string> Mails)
{
    public bool Any => Names.Count > 0;
}

/// One cfg.Exemption row with the #252 columns (NULL on a row made before them).
public sealed record ExemptionInfo(long ExemptionId, string Scope, string? ReportName, string? ConfigurationId, string? Cve, string? AssetKey, string Reason,
    DateTime? ExpiresAt, string CreatedBy, DateTime CreatedAt, DateTime? RevokedAt, string? RevokedBy, long? RequestId, string? Domain,
    string? ApprovedBy, DateTime? ApprovedAt, string? ReviewedBy, DateTime? ReviewedAt, string? AssetName = null, string? Category = null)
{
    /// active | expired | ended
    public string State(DateTime now) => RevokedAt is not null ? ExemptionStates.Ended : ExpiresAt is { } e && e <= now ? ExemptionStates.Expired : ExemptionStates.Active;

    /// The domain it is filed under: its own, else '*' (made before domains existed).
    public string DomainKey => string.IsNullOrWhiteSpace(Domain) ? DomainRoles.AnyDomain : Domain!;

    /// When it was last looked at by a person: the last review, else the approval, else its creation.
    public DateTime LastReviewed => ReviewedAt ?? ApprovedAt ?? CreatedAt;

    /// An ACTIVE exemption nobody has reviewed within the review window.
    public bool IsReviewOverdue(DateTime now, int overdueDays) => State(now) == ExemptionStates.Active && LastReviewed < now.AddDays(-overdueDays);

    public bool IsExpiringWithin(DateTime now, int days) => State(now) == ExemptionStates.Active && ExpiresAt is { } e && e <= now.AddDays(days);

    public string Approver => ApprovedBy ?? CreatedBy;

    public RequestItem AsItem() => new(Scope, ReportName, ConfigurationId, Cve, AssetKey, AssetName, null, ExemptionId, Category);

    /// The finding's category as the roster keys it (#283; null on an exemption made before categories were carried).
    public string? CategoryKey => DomainRoles.NormalizeCategory(Category);

    /// "Endpoint" or "Endpoint / Vulnerabilities".
    public string ScopeLabel => DomainRoles.Label(DomainKey, CategoryKey);
}

/// A mail for the outbox: the close-loop mail job sends it through the one SMTP path.
public sealed record QueuedMail(string Kind, long? RequestId, string? Domain, IReadOnlyList<string> To, string Subject, string BodyHtml)
{
    public const string Request = "request";
    public const string Decision = "decision";
}
