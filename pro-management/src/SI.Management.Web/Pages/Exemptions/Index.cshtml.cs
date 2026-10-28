using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Exemptions;

namespace SI.Management.Web.Pages.Exemptions;

/// <summary>
/// Exemptions (#252): the requests waiting for MY decision, my own requests, and every exemption with its state --
/// active, expiring, expired, ended -- and the "review overdue" flag. Admin or Viewer; who may decide or review is
/// decided per domain by <see cref="ExemptionWorkflow"/>.
/// </summary>
public sealed class IndexModel : SI.Management.Web.Columns.DataViewPageModel
{
    public static readonly string[] Views = ["decide", "mine", "requests", "active", "expiring", "expired", "overdue", "ended", "all"];
    private readonly ExemptionWorkflow _flow;
    private readonly ILogger<IndexModel> _log;
    public IndexModel(ExemptionWorkflow flow, ILogger<IndexModel> log) { _flow = flow; _log = log; }

    [BindProperty(SupportsGet = true)] public string? View { get; set; }
    [BindProperty(SupportsGet = true)] public string? Dom { get; set; }

    public string Current => Views.Contains(View) ? View! : "active";
    public DateTime Now { get; private set; }
    public ExemptionSettings.Values Settings { get; private set; } = ExemptionSettings.Values.Defaults;
    public Roster Roster { get; private set; } = new(Array.Empty<DomainRoleRow>());
    public IReadOnlyList<RequestRow> Requests { get; private set; } = Array.Empty<RequestRow>();
    public IReadOnlyList<ExemptionInfo> Exemptions { get; private set; } = Array.Empty<ExemptionInfo>();
    public string? Error { get; private set; }

    public string Me => User.ChangeName();
    public IReadOnlyList<RequestRow> ToDecide => Requests.Where(r => r.State == ExemptionStates.Requested
        && (ExemptionWorkflow.CanDecide(User, Roster, r.Domain, r.Category) || AsBusinessApprover.Contains(r.RequestId))).ToList();
    /// #391: the waiting requests routed to a department this user is a business approver of.
    public IReadOnlySet<long> AsBusinessApprover { get; private set; } = new HashSet<long>();
    public IReadOnlyList<RequestRow> Mine => Requests.Where(r => string.Equals(r.RequestedBy, Me, StringComparison.OrdinalIgnoreCase)).ToList();
    public IEnumerable<ExemptionInfo> InDomain => Exemptions.Where(e => Dom is null || string.Equals(e.DomainKey, Dom, StringComparison.OrdinalIgnoreCase));
    public int Active => InDomain.Count(e => e.State(Now) == ExemptionStates.Active);
    public int Expiring => InDomain.Count(e => e.IsExpiringWithin(Now, Math.Max(Settings.ExpiryWarningDays, 1)));
    public int Expired => InDomain.Count(e => e.State(Now) == ExemptionStates.Expired);
    public int Overdue => InDomain.Count(e => e.IsReviewOverdue(Now, Settings.ReviewOverdueDays));
    public bool MayReviewAny => User.IsAdmin() || Roster.IsAnyOwner(Me);

    public IReadOnlyList<RequestRow> ShownRequests => Current switch
    {
        "decide" => ToDecide,
        "mine" => Mine,
        _ => Requests,
    };

    public IReadOnlyList<ExemptionInfo> ShownExemptions => Current switch
    {
        "expiring" => InDomain.Where(e => e.IsExpiringWithin(Now, Math.Max(Settings.ExpiryWarningDays, 1))).OrderBy(e => e.ExpiresAt).ToList(),
        "expired" => InDomain.Where(e => e.State(Now) == ExemptionStates.Expired).ToList(),
        "overdue" => InDomain.Where(e => e.IsReviewOverdue(Now, Settings.ReviewOverdueDays)).OrderBy(e => e.LastReviewed).ToList(),
        "ended" => InDomain.Where(e => e.State(Now) == ExemptionStates.Ended).ToList(),
        "all" => InDomain.ToList(),
        _ => InDomain.Where(e => e.State(Now) == ExemptionStates.Active).ToList(),
    };

    public bool ShowsRequests => Current is "decide" or "mine" or "requests";

    public async Task OnGetAsync(CancellationToken ct)
    {
        Now = _flow.Now;
        try
        {
            Settings = await _flow.SettingsAsync(ct);
            if (!await _flow.ReadyAsync(ct)) { Error = "This database does not have the exemption request tables yet: run the Pro settings setup (setup\\Import-SIProSettings.ps1 -- it only adds)."; return; }
            Roster = await _flow.RosterAsync(ct);
            Requests = await _flow.RequestsAsync(null, ct);
            AsBusinessApprover = await _flow.DecidedAsBusinessApproverAsync(User, Requests, ct);
            Exemptions = await _flow.ExemptionsAsync(ct);
            if (View is null && ToDecide.Count > 0) View = "decide";
            if (!Exporting) await LoadTablesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the exemptions failed");
            Error = "The exemptions could not be read from the Pro database: " + ex.Message;
        }
    }

    // ---- #589 the tables: every column, the chooser, the all-rows exports ------------------------------------------

    protected override Task LoadForExportAsync(CancellationToken ct) => OnGetAsync(ct);

    private static string StateBadge(string s) => s switch { "active" or "approved" => "good", "expired" or "rejected" => "bad", "requested" => "warn", _ => "" };

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables()
    {
        if (ShowsRequests)
        {
            var requests = new SI.Management.Web.Columns.DataTable
            {
                Id = "requests", View = "exemptions-requests", Title = "Exemption requests", Rows = ShownRequests.Cast<object>().ToList(), Marker = "data-requests",
                RowAttributes = o => { var r = (RequestRow)o; return new Dictionary<string, string?> { ["data-request"] = r.RequestId.ToString(System.Globalization.CultureInfo.InvariantCulture), ["data-state"] = r.State }; },
                Columns =
                [
                    new("RequestId", "Request", o => ((RequestRow)o).RequestId, Text: o => "#" + ((RequestRow)o).RequestId, Link: o => "/Exemptions/Decide?id=" + ((RequestRow)o).RequestId),
                    new("Domain", "Domain", o => ((RequestRow)o).ScopeLabel),
                    new("ItemCount", "Findings", o => ((RequestRow)o).ItemCount, Number: true),
                    new("RequestedBy", "Requested by", o => ((RequestRow)o).RequestedBy),
                    new("RequestedAt", "Requested", o => ((RequestRow)o).RequestedAt),
                    new("ExpiresAt", "Until", o => ((RequestRow)o).ExpiresAt, Text: o => ExemptionPeriods.Describe(((RequestRow)o).ExpiresAt)),
                    new("State", "State", o => ((RequestRow)o).State),
                    new("DecidedBy", "Decided by", o => ((RequestRow)o).DecidedBy),
                    new("DecisionComment", "Comment", o => ((RequestRow)o).DecisionComment),
                    new("Reason", "Reason", o => ((RequestRow)o).Reason),
                    new("Category", "Category", o => ((RequestRow)o).Category),
                    new("DecidedAt", "Decided", o => ((RequestRow)o).DecidedAt),
                    new("Approver", "Approver asked", o => ((RequestRow)o).Approver),
                    new("Source", "Requested from", o => ((RequestRow)o).Source),
                    new("Routing", "Routed to", o => ((RequestRow)o).Routing is null ? null : ExemptionRouting.Describe(((RequestRow)o).Routing, null)),
                ],
            };
            requests.Html["State"] = o => SI.Management.Web.Columns.DataCellHtml.Badges((StateBadge(((RequestRow)o).State), ((RequestRow)o).State));
            return [requests];
        }
        var now = Now;
        var exemptions = new SI.Management.Web.Columns.DataTable
        {
            Id = "exemptions", View = "exemptions", Title = "Exemptions", Rows = ShownExemptions.Cast<object>().ToList(), Marker = "data-exemptions",
            Ci = SI.Management.Core.ProData.RowCiKey.AssetKey, Findings = SI.Management.Core.ProData.RowFindingKey.Issue, CollectionId = "",
            RefOf = o => { var e = (ExemptionInfo)o; return new SI.Management.Web.Columns.RowRef(e.AssetKey, null, e.Cve ?? e.ConfigurationId); },
            RowAttributes = o =>
            {
                var e = (ExemptionInfo)o;
                return new Dictionary<string, string?>
                {
                    ["data-exemption"] = e.ExemptionId.ToString(System.Globalization.CultureInfo.InvariantCulture), ["data-state"] = e.State(now),
                    ["data-overdue"] = e.IsReviewOverdue(now, Settings.ReviewOverdueDays) ? "1" : "0",
                };
            },
            Columns =
            [
                new("ExemptionId", "Id", o => ((ExemptionInfo)o).ExemptionId),
                new("Domain", "Domain", o => ((ExemptionInfo)o).ScopeLabel),
                new("What", "What", o => ((ExemptionInfo)o).AsItem().Describe()),
                new("AssetName", "Asset", o => ((ExemptionInfo)o).AssetName),
                new("AssetKey", "Asset (CI) key", o => ((ExemptionInfo)o).AssetKey),
                new("Cve", "CVE", o => ((ExemptionInfo)o).Cve),
                new("ConfigurationId", "Configuration", o => ((ExemptionInfo)o).ConfigurationId),
                new("ReportName", "Report", o => ((ExemptionInfo)o).ReportName),
                new("Reason", "Reason", o => ((ExemptionInfo)o).Reason),
                new("Approver", "Approved by", o => ((ExemptionInfo)o).Approver),
                new("ExpiresAt", "Until", o => ((ExemptionInfo)o).ExpiresAt, Text: o => ExemptionPeriods.Describe(((ExemptionInfo)o).ExpiresAt)),
                new("State", "State", o => ((ExemptionInfo)o).State(now)),
                new("LastReviewed", "Last reviewed", o => ((ExemptionInfo)o).LastReviewed),
                new("ReviewedBy", "Reviewed by", o => ((ExemptionInfo)o).ReviewedBy),
                new("CreatedBy", "Created by", o => ((ExemptionInfo)o).CreatedBy),
                new("CreatedAt", "Created", o => ((ExemptionInfo)o).CreatedAt),
                new("RequestId", "Request", o => ((ExemptionInfo)o).RequestId, Link: o => ((ExemptionInfo)o).RequestId is { } id ? "/Exemptions/Decide?id=" + id : null),
                new("Scope", "Scope", o => ((ExemptionInfo)o).Scope),
                new("Category", "Category", o => ((ExemptionInfo)o).Category),
                new("RevokedAt", "Ended", o => ((ExemptionInfo)o).RevokedAt),
                new("RevokedBy", "Ended by", o => ((ExemptionInfo)o).RevokedBy),
            ],
        };
        exemptions.Html["State"] = o =>
        {
            var e = (ExemptionInfo)o;
            var st = e.State(now);
            return SI.Management.Web.Columns.DataCellHtml.Badges((StateBadge(st), st), ("warn", e.IsReviewOverdue(now, Settings.ReviewOverdueDays) ? "review overdue" : null));
        };
        exemptions.Html["LastReviewed"] = o => SI.Management.Web.Columns.DataCellHtml.WithMuted(Fmt.When(((ExemptionInfo)o).LastReviewed), ((ExemptionInfo)o).ReviewedBy);
        return [exemptions];
    }
}
