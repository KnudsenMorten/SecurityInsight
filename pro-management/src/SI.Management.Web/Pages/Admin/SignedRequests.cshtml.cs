using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Data;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Configuration &gt; Signed requests (OPEN-04; framework 12.11f item 2; owner 2026-11-04, framework REQUIREMENTS.md:64-65:
/// "observe (log only) ... then ENFORCE ring by ring ..., each install with one SuperAdmin-signed adoption step"). Shows the
/// configuration the pipeline runner RECORDED (per kind the row count + SHA-256, and the recorded hash), whether the install
/// is still observe only ("Waiting for adoption by a SuperAdmin") or enforced, how many changes would have been refused in the
/// last 14 days, and the adoption requests. A SuperAdmin ADOPTS exactly the recorded set: the request carries the hash the
/// page showed and -- through the global audit filter -- the person's own signed token; the runner verifies both (and that
/// the person is a SuperAdmin) before enforcement starts. Nothing here changes the configuration itself.
/// </summary>
public sealed class SignedRequestsModel : PageModel
{
    public const string StateSql = "IF OBJECT_ID(N'cfg.SignedRequestEnforcement') IS NULL SELECT CAST(NULL AS NVARCHAR(64)) AS RecordedHash WHERE 1 = 0; ELSE SELECT StartedUtc, RecordedHash, Manifest, AdoptedUtc, AdoptedBy FROM cfg.SignedRequestEnforcement WHERE Id = 1;";
    public const string RequestsSql = "IF OBJECT_ID(N'cfg.SignedRequestAdoption') IS NULL SELECT CAST(NULL AS NVARCHAR(256)) AS RequestedBy WHERE 1 = 0; ELSE SELECT TOP (5) RequestedBy, RequestedUtc, Decision, Reason, DecidedUtc FROM cfg.SignedRequestAdoption ORDER BY AdoptionId DESC;";
    public const string WouldSql = "SELECT COUNT(*) AS N FROM cfg.AuditEvent WHERE Action = N'signedrequest.change.would-refuse' AND TsUtc >= DATEADD(DAY, -14, SYSUTCDATETIME());";
    public const string AdoptSql = "INSERT INTO cfg.SignedRequestAdoption (RecordedHash, RequestedBy, CorrelationId) VALUES (@Hash, @By, @Cid);";
    public const string Waiting = "Waiting for adoption by a SuperAdmin";

    private readonly ISqlExecutor _sql;
    private readonly ILogger<SignedRequestsModel> _log;
    public SignedRequestsModel(ISqlExecutor sql, ILogger<SignedRequestsModel> log) { _sql = sql; _log = log; }

    public sealed record Kind(string Name, long Rows, string Sha256);
    public sealed record Request(string By, DateTime? At, string? Decision, string? Reason);

    public bool Recorded { get; private set; }
    public DateTime? RecordedUtc { get; private set; }
    public string RecordedHash { get; private set; } = "";
    public DateTime? AdoptedUtc { get; private set; }
    public string? AdoptedBy { get; private set; }
    public List<Kind> Kinds { get; } = new();
    public List<Request> Requests { get; } = new();
    public long WouldRefuse { get; private set; }
    public string? Error { get; private set; }
    public string? Problem { get; private set; }
    public bool Adopted => AdoptedUtc is not null;

    [BindProperty] public string? Hash { get; set; }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    /// PURE. The hash a SuperAdmin adopts must be exactly the recorded one (the runner checks it again).
    public static bool SameHash(string? asked, string? recorded) =>
        !string.IsNullOrWhiteSpace(asked) && !string.IsNullOrWhiteSpace(recorded) && string.Equals(asked.Trim(), recorded.Trim(), StringComparison.OrdinalIgnoreCase);

    private static DateTime? Time(object? v) => v switch { DateTime d => DateTime.SpecifyKind(d, DateTimeKind.Utc), _ => null };

    private async Task LoadAsync(CancellationToken ct)
    {
        try
        {
            var row = (await _sql.QueryAsync(StateSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
            if (row is not null)
            {
                Recorded = true;
                RecordedUtc = Time(row.GetValueOrDefault("StartedUtc"));
                RecordedHash = row.GetValueOrDefault("RecordedHash") as string ?? "";
                AdoptedUtc = Time(row.GetValueOrDefault("AdoptedUtc"));
                AdoptedBy = row.GetValueOrDefault("AdoptedBy") as string;
                if (row.GetValueOrDefault("Manifest") is string m && m.Length > 0)
                {
                    using var doc = JsonDocument.Parse(m);
                    if (doc.RootElement.TryGetProperty("kinds", out var ks) && ks.ValueKind == JsonValueKind.Array)
                        foreach (var k in ks.EnumerateArray())
                            Kinds.Add(new Kind(k.GetProperty("kind").GetString() ?? "", k.GetProperty("rows").GetInt64(), k.GetProperty("sha256").GetString() ?? ""));
                }
            }
            foreach (var r in await _sql.QueryAsync(RequestsSql, new Dictionary<string, object?>(), ct))
                Requests.Add(new Request(r.GetValueOrDefault("RequestedBy") as string ?? "", Time(r.GetValueOrDefault("RequestedUtc")), r.GetValueOrDefault("Decision") as string, r.GetValueOrDefault("Reason") as string));
            var w = (await _sql.QueryAsync(WouldSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
            WouldRefuse = w?.GetValueOrDefault("N") is { } n ? Convert.ToInt64(n, System.Globalization.CultureInfo.InvariantCulture) : 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the signed-request state could not be read");
            Error = "The signed-request state could not be read from the database: " + ex.Message;
        }
    }

    /// A SuperAdmin adopts EXACTLY the recorded configuration. Signed by the global audit filter with the person's own
    /// token; the pipeline runner decides it at its next wake-up.
    [Audited("signedrequest.adoption.request")]
    public async Task<IActionResult> OnPostAdoptAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        await LoadAsync(ct);
        var audit = AuditScope.Current;
        if (audit is not null) { audit.Target = "/Admin/SignedRequests|hash=" + (Hash ?? ""); }
        string? why = null;
        if (Error is not null) why = Error;
        else if (!Recorded) why = "Nothing is recorded for adoption yet: the pipeline runner records the configuration at its next wake-up.";
        else if (Adopted) why = "This install is already adopted: signed requests are enforced.";
        else if (!SameHash(Hash, RecordedHash)) why = "The hash you adopt is not the recorded one: open the page again and adopt what it shows.";
        if (why is not null)
        {
            audit?.Refused(why);
            Problem = why;
            return Page();
        }
        await _sql.QueryAsync(AdoptSql, new Dictionary<string, object?>
        {
            ["Hash"] = RecordedHash, ["By"] = AuditScope.ActorOf(User), ["Cid"] = audit?.CorrelationId,
        }, ct);
        TempData["toast"] = "Adoption sent, signed with your sign-in. The pipeline runner verifies it at its next wake-up (within 5 minutes); then signed requests are enforced.";
        return Redirect("/Admin/SignedRequests");
    }
}
