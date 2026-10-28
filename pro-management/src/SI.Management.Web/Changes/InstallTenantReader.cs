using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>
/// The tenant this install serves, as it was RECORDED from the tenant itself: cfg.InstallState 'Tenant', compact JSON
/// { tenantId, name, initialDomain, setBy, setAt }. Written by setup\Set-SIInstallTenant.ps1 (the guided install and
/// Bootstrap-ContainerAppJob.ps1 run it), which reads the Entra organization (display name + the initial
/// onmicrosoft.com domain) through Microsoft Graph -- the name is never typed by hand. The header shows it as TENANT.
/// </summary>
public sealed record InstallTenant(string? TenantId, string? Name, string? InitialDomain, string? SetBy, DateTime? SetAt);

public sealed class InstallTenantReader
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value, UpdatedAt FROM cfg.InstallState WHERE Name = N'Tenant';
""";

    private readonly ISqlExecutor _sql;
    public InstallTenantReader(ISqlExecutor sql) => _sql = sql;

    /// null = nothing recorded.
    public async Task<InstallTenant?> ReadAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
        return row is null ? null : Parse(row.Str("Value"));
    }

    /// The row's value, or null when it names neither a tenant name nor a domain.
    public static InstallTenant? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return null;
            static string? S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { } s && s.Trim().Length > 0 ? s.Trim() : null;
            var name = S(o, "name");
            var domain = S(o, "initialDomain");
            if (name is null && domain is null) return null;
            DateTime? at = DateTime.TryParse(S(o, "setAt"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            return new InstallTenant(S(o, "tenantId"), name, domain, S(o, "setBy"), at);
        }
        catch (JsonException) { return null; }
    }
}
