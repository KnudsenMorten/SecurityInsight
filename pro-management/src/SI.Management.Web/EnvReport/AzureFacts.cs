using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;

namespace SI.Management.Web.EnvReport;

/// One Azure resource of the install as ARM reported it: name, type, location, its network facts (public access, IP
/// restrictions, the default network rule) and its identity (system-assigned principal, user-assigned identities).
public sealed record AzureResource(string Id, string Name, string Type, string? Location, IReadOnlyList<(string Fact, string Value)> Network,
    string? PrincipalId = null, IReadOnlyList<string>? UserAssigned = null, string? ClientId = null)
{
    public string Kind => Type switch
    {
        var t when t.Equals("Microsoft.App/containerApps", StringComparison.OrdinalIgnoreCase) => "container app",
        var t when t.Equals("Microsoft.App/jobs", StringComparison.OrdinalIgnoreCase) => "container app job",
        var t when t.Equals("Microsoft.App/managedEnvironments", StringComparison.OrdinalIgnoreCase) => "container apps environment",
        var t when t.Equals("Microsoft.Sql/servers", StringComparison.OrdinalIgnoreCase) => "SQL server",
        var t when t.Equals("Microsoft.Sql/servers/databases", StringComparison.OrdinalIgnoreCase) => "SQL database",
        var t when t.Equals("Microsoft.KeyVault/vaults", StringComparison.OrdinalIgnoreCase) => "Key Vault",
        var t when t.Equals("Microsoft.ContainerRegistry/registries", StringComparison.OrdinalIgnoreCase) => "container registry",
        var t when t.Equals("Microsoft.Storage/storageAccounts", StringComparison.OrdinalIgnoreCase) => "storage account",
        var t when t.Equals("Microsoft.ManagedIdentity/userAssignedIdentities", StringComparison.OrdinalIgnoreCase) => "managed identity",
        var t when t.Equals("Microsoft.OperationalInsights/workspaces", StringComparison.OrdinalIgnoreCase) => "Log Analytics workspace",
        var t when t.Equals("Microsoft.Insights/dataCollectionRules", StringComparison.OrdinalIgnoreCase) => "data collection rule",
        var t when t.Equals("Microsoft.Network/natGateways", StringComparison.OrdinalIgnoreCase) => "NAT gateway",
        var t when t.Equals("Microsoft.Network/privateEndpoints", StringComparison.OrdinalIgnoreCase) => "private endpoint",
        var t when t.Equals("Microsoft.Network/virtualNetworks", StringComparison.OrdinalIgnoreCase) => "virtual network",
        _ => Type,
    };
}

/// One Azure role assignment at the install's resource group (or above it): who, which role, where.
public sealed record AzureRoleAssignment(string PrincipalId, string PrincipalType, string Role, string Scope);

/// What ARM said when the UPDATER read it (<see cref="ReadUtc"/>); <see cref="Error"/> = it could not be read (the report
/// says so and shows the rest).
public sealed record AzureFacts(string? SubscriptionId, string? ResourceGroup, IReadOnlyList<AzureResource> Resources, IReadOnlyList<AzureRoleAssignment> Roles, string? Error,
    DateTime? ReadUtc = null)
{
    public static AzureFacts NotConfigured => new(null, null, Array.Empty<AzureResource>(), Array.Empty<AzureRoleAssignment>(),
        "the Pro database is not configured for the web app -- the Azure part cannot be read");

    public static AzureFacts NotReadYet => new(null, null, Array.Empty<AzureResource>(), Array.Empty<AzureRoleAssignment>(),
        "not read yet: the updater records the install's Azure resources and role assignments on its next run");

    /// PURE. "read by the updater 2026-11-15 18:30 UTC (3 hours ago)" -- the facts' age, as the page shows it.
    public string? AgeText(DateTime nowUtc)
    {
        if (ReadUtc is not { } at) return null;
        var span = nowUtc - at;
        var ago = span.TotalMinutes < 1 ? "just now"
            : span.TotalHours < 1 ? $"{(int)span.TotalMinutes} minute(s) ago"
            : span.TotalDays < 2 ? $"{(int)span.TotalHours} hour(s) ago"
            : $"{(int)span.TotalDays} days ago";
        return $"read by the updater {at.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC ({ago})";
    }
}

public interface IAzureFactsReader
{
    Task<AzureFacts> ReadAsync(CancellationToken ct);
}

/// <summary>
/// SI #1268 (the owner's approved rights list, 2026-11-15): the web app holds NO Reader on the install's resource group and
/// never calls ARM for this report. The UPDATER reads the facts with its own rights on every run
/// (container\updater\_shared\SI-UpdaterEnvFacts.ps1) and writes them to the Pro database -- cfg.EnvironmentFacts row
/// 'install', compact JSON { readUtc, subscriptionId, resourceGroup, resources, roles, error } -- and this reader
/// takes them from there, with their read time (the page shows their age). Only named facts are in the row, never a key or
/// a secret. Garbage or no row = "not read yet", never a broken page.
/// </summary>
public sealed class SqlAzureFactsReader(ISqlExecutor sql) : IAzureFactsReader
{
    public const string RowName = "install";
    public const string Sql = """
IF OBJECT_ID(N'cfg.EnvironmentFacts') IS NOT NULL SELECT Facts AS Value, ReadUtc AS UpdatedAt FROM cfg.EnvironmentFacts WHERE Name = N'install';
""";

    public async Task<AzureFacts> ReadAsync(CancellationToken ct)
    {
        var rows = await sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
        return row is null ? AzureFacts.NotReadYet : Parse(row.Str("Value"), row.Date("UpdatedAt"));
    }

    /// PURE. The updater's row; -updatedAt (the row's own time) stands in when the JSON carries no read time.
    public static AzureFacts Parse(string? json, DateTime? updatedAt = null)
    {
        if (string.IsNullOrWhiteSpace(json)) return AzureFacts.NotReadYet;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return AzureFacts.NotReadYet;
            static string? S(JsonElement e, string n) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;
            static IEnumerable<JsonElement> A(JsonElement e, string n) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray() : Enumerable.Empty<JsonElement>();
            var resources = new List<AzureResource>();
            foreach (var r in A(o, "resources").Where(x => x.ValueKind == JsonValueKind.Object))
            {
                var id = S(r, "id") ?? "";
                var net = A(r, "network").Where(n => S(n, "fact") is not null && S(n, "value") is not null).Select(n => (S(n, "fact")!, S(n, "value")!)).ToList();
                var ua = A(r, "userAssigned").Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList();
                resources.Add(new AzureResource(id, S(r, "name") ?? id.Split('/').Last(), S(r, "type") ?? "", S(r, "location"), net, S(r, "principalId"), ua.Count == 0 ? null : ua, S(r, "clientId")));
            }
            var roles = A(o, "roles").Where(x => x.ValueKind == JsonValueKind.Object)
                .Select(a => new AzureRoleAssignment(S(a, "principalId") ?? "", S(a, "principalType") ?? "", S(a, "role") ?? "", S(a, "scope") ?? "")).ToList();
            DateTime? at = DateTime.TryParse(S(o, "readUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : updatedAt;
            return new AzureFacts(S(o, "subscriptionId"), S(o, "resourceGroup"), resources, roles, S(o, "error"), at);
        }
        catch (JsonException) { return AzureFacts.NotReadYet; }
    }
}
