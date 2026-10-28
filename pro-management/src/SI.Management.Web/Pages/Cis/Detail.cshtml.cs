using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Cis;

/// <summary>
/// One CI (V3-DATA-MODEL 2.13 "CI page"): the summary; its tier and how it was decided (every claim -- rule, stage,
/// mechanism, claimed tier, whether it was allowed to decide and why not, the winner marked); its criticality (the CMDB
/// value, the mapping, the factor); its risk factors (axis, impact, stage -- a testing factor counts 0); its coverage
/// gaps; its linked objects; where each field came from; its findings; its trend; and its provider records.
/// </summary>
public sealed class DetailModel : PageModel
{
    private readonly ICiViews _cis;
    private readonly ILogger<DetailModel> _log;
    private readonly SI.Management.Web.Changes.CiOverrideStore? _overrides;
    private readonly ICiGraphViews? _graph;

    public DetailModel(ICiViews cis, ILogger<DetailModel> log, SI.Management.Web.Changes.CiOverrideStore? overrides = null, ICiGraphViews? graph = null)
    { _cis = cis; _log = log; _overrides = overrides; _graph = graph; }

    /// #462 the manual overrides of this CI (in force, expired, recently removed); null = could not be read / no table.
    public IReadOnlyList<SI.Management.Web.Changes.CiOverrideRow>? Overrides { get; private set; }
    public DateTime NowUtc { get; } = DateTime.UtcNow;

    /// #493 / #494 / #495 / #496 the CI's services, relations, findings with their lifecycle and changes (empty until the
    /// CI build and the data sync of this release have run; a part that cannot be read is said, never an error page).
    public CiGraph Graph { get; private set; } = CiGraph.Empty;
    public string? GraphError { get; private set; }

    [BindProperty(SupportsGet = true)] public string? Id { get; set; }

    public bool NotLoaded { get; private set; }
    public CiDetail? Ci { get; private set; }
    public ChartSpec? TrendChart { get; private set; }
    public List<QueryInfo> Queries { get; } = new();
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(Id)) return Redirect("/Cis");
        try
        {
            var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
            if (resolver is not null && (await resolver.ResolveAsync(User, ct)).Rows is not null)
            {
                Error = "This view is not available to an account limited to departments: it shows CIs across every department.";
                return Page();
            }
            var schema = await _cis.SchemaAsync(ct);
            if (!schema.Data.Ci) { NotLoaded = true; return Page(); }
            var r = await _cis.CiAsync(Id, schema.Data, ct);
            Ci = r.Data;
            Queries.Add(QueryInfo.From(r, "This CI"));
            if (Ci is null) { Response.StatusCode = StatusCodes.Status404NotFound; Error = "That CI is not in the Pro database (it may have been retired, or the id is wrong)."; return Page(); }
            if (_overrides is not null)
            {
                try { if (await _overrides.TableExistsAsync(ct)) Overrides = await _overrides.ListAsync(Ci.Ci.CiId, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the manual overrides of CI {Id} could not be read", Id); }
            }
            if (_graph is not null)
            {
                try
                {
                    var g = await _graph.CiGraphAsync(Id, ct);
                    Graph = g.Data;
                    if (Graph.Schema.Any) Queries.Add(QueryInfo.From(g, "Services, relations, finding lifecycle and changes"));
                }
                catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException)
                {
                    _log.LogWarning(ex, "the graph of CI {Id} could not be read", Id);
                    GraphError = "The services, relations and history of this CI could not be read: " + ex.Message;
                }
            }
            if (Ci.Trend.Count > 0)
                TrendChart = new ChartSpec("ci-trend", "line", Ci.Trend.Select(d => Fmt.Day(d.Day)).ToList(), new[]
                {
                    new ChartSeries("Weighted asset risk score", Ci.Trend.Select(d => d.WeightedRiskScore).ToList(), 1),
                    new ChartSeries("Asset risk score", Ci.Trend.Select(d => d.RiskScore).ToList(), 2),
                    new ChartSeries("Open findings", Ci.Trend.Select(d => (double?)d.OpenFindings).ToList(), 3),
                }, null, "The CI's risk per day");
        }
        catch (ArgumentException ex) { Error = "The request is not valid: " + ex.Message; }
        catch (ViewTimeoutException ex) { Error = SI.Management.Web.Pages.Collection.CollectionPageModel.TimeoutText(ex.Limit, null); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the CI {Id} could not be read", Id);
            Error = "The CI could not be read from the Pro database: " + ex.Message;
        }
        return Page();
    }

    /// "Tier 2" / "Unclassified".
    public static string TierText(int? tier) => tier is >= 0 and <= 3 ? "Tier " + tier : "Unclassified";

    /// The tier dot's class suffix.
    public static string TierDot(int? tier) => tier is >= 0 and <= 3 ? tier.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : ProDataFilters.Unclassified;

    /// Who set the tier, in words.
    public static string SetByText(string? setBy) => setBy switch
    {
        "rule" => "a tier rule",
        "tag" => "your tag (no SI rule claims a tier)",
        "default" => "the default tier rule (no other rule matched)",
        "override" => "a pin (an Admin's override)",
        "cmdb" => "the CMDB",
        null or "" => "not recorded",
        _ => setBy,
    };

    /// #579 what kind of claim it is, in words.
    public static string ClaimKindText(string? kind) => kind switch
    {
        "rule" => "SI rule",
        "tag" => "your tag",
        "default" => "default",
        null or "" => "",
        _ => kind,
    };

    /// Why a claim did or did not decide, in words.
    public static string Decided(CiTierClaim c) => c.Winner ? "decided the tier" : c.Admissible ? "allowed, but another claim won" : "recorded only";

    /// How a criticality mapping reads.
    public static string MappingText(string? mapping) => mapping switch
    {
        "criticality" => "the criticality mapping",
        "default" => "no CMDB value -- the default factor",
        "unmapped value -> default" => "a value the mapping does not know -- the default factor",
        null or "" => "",
        _ => mapping,
    };

    /// How a CI came to belong to a service, in words.
    public static string ServiceSourceText(string? source) => source switch
    {
        "cmdb_link" => "linked on the CMDB page",
        "service_model" => "a service model rule",
        "cmdb" => "the CI's own CMDB record",
        null or "" => "",
        _ => source,
    };

    /// A relation kind in words ("owned_by" -> "owned by").
    public static string KindText(string kind) => kind.Replace('_', ' ');

    /// Who owns a finding, and where that came from.
    public static string OwnerSourceText(string? source) => source switch
    {
        "service" => "the CI's business service",
        "cmdb" => "the CI's CMDB record",
        "ci" => "the CI's owner",
        null or "" => "",
        _ => source,
    };

    /// A finding's status in words.
    public static string StatusText(string status) => status switch
    {
        "open" => "open",
        "reopened" => "reopened",
        "exempted" => "exempted",
        "fixed" => "fixed",
        "closed" => "closed",
        _ => status,
    };

    /// A changed field in words (the CI history).
    public static string FieldText(string field) => field switch
    {
        "ci" => "CI",
        "link" => "linked object",
        "finding" => "finding",
        "service" => "business service",
        "relation" => "relation",
        "relation_in" => "relation to this CI",
        "software" => "software",
        _ => field.StartsWith("si_", StringComparison.Ordinal) ? SI.Management.Core.ProData.CiColumns.LabelOf(field) : field,
    };

    /// A number from a document (invariant text) in the viewer's format; anything else as it is.
    public static string Value(string text) =>
        double.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) && text.Trim().Length > 0 && !text.Contains(':')
            ? ScoreFormat.Number(d) : text;
}
