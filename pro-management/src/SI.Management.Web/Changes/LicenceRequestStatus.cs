using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>
/// The licence request state the updater keeps (#239): none / requested / pending / approved / rejected, the licence's
/// valid-to and the last check. The updater writes it as compact JSON into cfg.InstallState 'LicenceRequest' (the pull
/// token is never in it); this page only reads it.
/// </summary>
public sealed record LicenceRequestState(string Status, DateTime? RequestedUtc, DateTime? NextPollUtc, DateTime? LastCheckUtc,
                                         string? ValidTo, string? Reason, string? LastError, DateTime? UpdatedAt)
{
    public string Summary => Status switch
    {
        "requested" or "pending" => $"Licence requested on {When(RequestedUtc)}, waiting for Invardia" + (NextPollUtc is null ? "." : $" (next check {When(NextPollUtc)})."),
        "approved" => "Licence installed" + (string.IsNullOrEmpty(ValidTo) ? "." : $", valid until {ValidTo}."),
        "rejected" => "The licence request was REJECTED by Invardia" + (string.IsNullOrEmpty(Reason) ? "." : $": {Reason}.") + " Contact Invardia (info@invardia.com), then run setup/Request-SILicense.ps1 -Force.",
        _ => string.IsNullOrEmpty(ValidTo) ? "No licence has been requested." : $"No request needed -- the licence is valid until {ValidTo}.",
    };

    private static string When(DateTime? d) => d is null ? "-" : d.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + "Z";
}

public sealed class LicenceRequestReader
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value, UpdatedAt FROM cfg.InstallState WHERE Name = N'LicenceRequest';
""";

    private static readonly string[] States = { "none", "requested", "pending", "approved", "rejected" };
    private readonly ISqlExecutor _sql;
    public LicenceRequestReader(ISqlExecutor sql) => _sql = sql;

    /// null = nothing recorded (no updater has run the licence step on this install).
    public async Task<LicenceRequestState?> ReadAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
        return row is null ? null : Parse(row.Str("Value"), row.Date("UpdatedAt"));
    }

    public static LicenceRequestState? Parse(string? json, DateTime? updatedAt)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            string? S(string n) => o.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            DateTime? D(string n) => DateTime.TryParse(S(n), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            var status = S("status") ?? "none";
            if (!States.Contains(status)) status = "none";
            return new LicenceRequestState(status, D("requestedUtc"), D("nextPollUtc"), D("lastCheckUtc"), S("validTo"), S("reason"), S("lastError"), updatedAt);
        }
        catch (JsonException) { return null; }
    }
}
