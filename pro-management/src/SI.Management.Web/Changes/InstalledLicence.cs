using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// What the Licence card says about the installed licence, worst first.
public enum LicenceState { NotChecked, Missing, Invalid, WrongTenant, Expired, InGrace, NotYetValid, EndsSoon, Valid }

/// <summary>
/// The INSTALLED licence (Key Vault secret SI-License) as the updater job last verified it -- with the same offline
/// checks the engines use (Get-SILicense: the signature, the dates, the tenant) -- and wrote into cfg.InstallState
/// 'Licence'. The web app never reads the licence secret itself: one verifier (the engines'), no secret in the web app.
/// The dates were proven by the signature when it was verified, so the state is worked out again from them for today
/// (a licence verified last night that ends today reads as ended today).
/// </summary>
public sealed record InstalledLicence(string Status, string? LicenceId, string? Customer, string? Sku, string? Features, bool? TenantOk,
    DateTime? ValidFrom, DateTime? ValidTo, DateTime? GraceUntil, string? Reason, DateTime? VerifiedUtc, IReadOnlyDictionary<string, int>? Limits = null)
{
    /// A licence ending within this many days says so (the updater asks for a renewal from the same point).
    public const int EndsSoonDays = 30;

    public LicenceState StateOn(DateTime todayUtc)
    {
        var today = todayUtc.Date;
        switch (Status)
        {
            case "Missing": return LicenceState.Missing;
            case "Invalid": return LicenceState.Invalid;
        }
        if (TenantOk == false) return LicenceState.WrongTenant;
        if (ValidTo is not { } to) return LicenceState.Invalid;
        if (ValidFrom is { } from && today < from.Date) return LicenceState.NotYetValid;
        if (today <= to.Date) return (to.Date - today).TotalDays <= EndsSoonDays ? LicenceState.EndsSoon : LicenceState.Valid;
        if (GraceUntil is { } g && today <= g.Date) return LicenceState.InGrace;
        return LicenceState.Expired;
    }

    /// The words and the colour (good / warn / bad) for a state.
    public static (string Text, string Tone) Describe(LicenceState s) => s switch
    {
        LicenceState.Valid => ("Valid", "good"),
        LicenceState.EndsSoon => ("Ends soon", "warn"),
        LicenceState.NotYetValid => ("Not valid yet", "warn"),
        LicenceState.InGrace => ("In grace", "bad"),
        LicenceState.Expired => ("Expired", "bad"),
        LicenceState.WrongTenant => ("Wrong tenant", "bad"),
        LicenceState.Invalid => ("Does not verify", "bad"),
        LicenceState.Missing => ("Missing", "bad"),
        _ => ("Not checked yet", "warn"),
    };

    /// What happens now, in one sentence, for the states that need a person.
    public string? NextStep(LicenceState s) => s switch
    {
        LicenceState.Missing => "No licence is installed, so the Pro jobs do not run (SecurityInsight runs as Community). The updater job asks Invardia for one every night while automatic licence requests are on; or install one with setup\\Set-SILicense.ps1." + LicenceRoute,
        LicenceState.Invalid => "The installed licence does not verify, so the Pro jobs do not run" + (string.IsNullOrEmpty(Reason) ? "." : $" ({Reason}).") + " Install a licence from Invardia with setup\\Set-SILicense.ps1." + LicenceRoute,
        LicenceState.WrongTenant => "The licence is for another tenant, so the Pro jobs do not run here. Ask Invardia for a licence for this tenant." + LicenceRoute,
        LicenceState.Expired => "The licence and its grace period have ended, so the Pro jobs do not run. Renew it with Invardia." + LicenceRoute,
        LicenceState.InGrace => "The licence has ended; the Pro jobs keep running until the grace period ends" + (GraceUntil is { } g ? " on " + Day(g) : "") + ". Renew it now." + LicenceRoute,
        LicenceState.EndsSoon => "The updater job asks Invardia for the renewal by itself while automatic licence requests are on.",
        LicenceState.NotYetValid => "The licence starts" + (ValidFrom is { } f ? " on " + Day(f) : " later") + "; until then the Pro jobs do not run.",
        _ => null,
    };

    /// Invardia's official licence route (brand.ts): licences arrive by mail and in the portal; info@ is the one contact.
    public const string LicenceRoute = " Licences: https://portal.invardia.com/ > Licences, or info@invardia.com.";

    public static string Day(DateTime d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}

public sealed class InstalledLicenceReader
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value, UpdatedAt FROM cfg.InstallState WHERE Name = N'Licence';
""";

    private static readonly string[] Statuses = { "Valid", "Grace", "Expired", "NotYetValid", "Invalid", "Missing" };
    private readonly ISqlExecutor _sql;
    public InstalledLicenceReader(ISqlExecutor sql) => _sql = sql;

    /// null = nothing recorded yet (the updater job has not verified the installed licence on this install).
    public async Task<InstalledLicence?> ReadAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
        return row is null ? null : Parse(row.Str("Value"));
    }

    /// The compact JSON the updater writes (ConvertTo-SILicenceSummaryJson). Garbage reads as nothing recorded.
    public static InstalledLicence? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return null;
            string? S(string n) => o.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;
            DateTime? D(string n) => DateTime.TryParse(S(n), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            bool? B(string n) => o.TryGetProperty(n, out var v) ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null } : null;
            var status = S("status") ?? "Missing";
            if (!Statuses.Contains(status)) status = "Invalid";
            // LICENCE-DIMENSION: the signed limits of a Pro Business licence as the updater read them; no object = Enterprise.
            // A value that is not a whole number is dropped, never guessed.
            Dictionary<string, int>? limits = null;
            if (o.TryGetProperty("limits", out var lim) && lim.ValueKind == JsonValueKind.Object)
            {
                limits = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                foreach (var p in lim.EnumerateObject())
                    if (p.Value.ValueKind == JsonValueKind.Number && p.Value.TryGetInt32(out var n) && n >= 0) limits[p.Name] = n;
            }
            return new InstalledLicence(status, S("licenceId"), S("customer"), S("sku"), S("features"), B("tenantOk"),
                D("validFrom"), D("validTo"), D("graceUntil"), S("reason"), D("verifiedUtc"), limits);
        }
        catch (JsonException) { return null; }
    }
}
