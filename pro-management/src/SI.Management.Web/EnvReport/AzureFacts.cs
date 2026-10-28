using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Azure.Core;
using Microsoft.Extensions.Options;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.EnvReport;

/// One Azure resource of the install as ARM reports it now: name, type, location, its network facts (public access, IP
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

/// What ARM said, read now; <see cref="Error"/> = it could not be read (the report says so and shows the rest).
public sealed record AzureFacts(string? SubscriptionId, string? ResourceGroup, IReadOnlyList<AzureResource> Resources, IReadOnlyList<AzureRoleAssignment> Roles, string? Error)
{
    public static AzureFacts NotConfigured => new(null, null, Array.Empty<AzureResource>(), Array.Empty<AzureRoleAssignment>(),
        "the web app does not know its resource group (settings Jobs:SubscriptionId / Jobs:ResourceGroup) -- the Azure part cannot be read");
}

public interface IAzureFactsReader
{
    Task<AzureFacts> ReadAsync(CancellationToken ct);
}

/// <summary>
/// The install's resource group read through ARM with the web app's own identity -- the Reader role it already holds there
/// (the Jobs page lists the jobs with it). One list call, one GET per resource whose network facts the report shows, the
/// role assignments of the group, and each role's name. Never a key or a secret: only named facts are taken from the
/// answers. Read-only; a failure is the report's "could not be read", never a broken page.
/// </summary>
public sealed class ArmAzureFactsReader(HttpClient http, TokenCredential cred, IOptions<JobsOptions> options, ILogger<ArmAzureFactsReader> log) : IAzureFactsReader
{
    private static readonly string[] Scopes = ["https://management.azure.com/.default"];
    public const int MaxResources = 120;

    /// The api-version to GET a resource type with (only the types whose network facts the report shows).
    public static string? ApiVersionOf(string type) => type.ToLowerInvariant() switch
    {
        "microsoft.app/containerapps" or "microsoft.app/jobs" => "2024-03-01",
        "microsoft.sql/servers" => "2023-08-01-preview",
        "microsoft.keyvault/vaults" => "2023-07-01",
        "microsoft.containerregistry/registries" => "2023-07-01",
        "microsoft.storage/storageaccounts" => "2023-05-01",
        "microsoft.managedidentity/userassignedidentities" => "2023-01-31",
        _ => null,
    };

    private async Task<JsonNode?> GetAsync(string url, CancellationToken ct)
    {
        var token = await cred.GetTokenAsync(new TokenRequestContext(Scopes), ct);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var resp = await http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"ARM GET returned {(int)resp.StatusCode}" + (resp.StatusCode == System.Net.HttpStatusCode.Forbidden ? " -- the web app's identity needs Reader on the resource group" : ""));
        return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
    }

    public async Task<AzureFacts> ReadAsync(CancellationToken ct)
    {
        var o = options.Value;
        if (!o.IsConfigured) return AzureFacts.NotConfigured;
        var rg = $"https://management.azure.com/subscriptions/{Uri.EscapeDataString(o.SubscriptionId)}/resourceGroups/{Uri.EscapeDataString(o.ResourceGroup)}";
        var resources = new List<AzureResource>();
        var roles = new List<AzureRoleAssignment>();
        string? error = null;
        try
        {
            var list = await GetAsync(rg + "/resources?api-version=2021-04-01", ct);
            foreach (var r in (list?["value"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().Take(MaxResources))
            {
                var id = r["id"]?.GetValue<string>() ?? "";
                var type = r["type"]?.GetValue<string>() ?? "";
                JsonNode? full = null;
                if (ApiVersionOf(type) is { } v)
                {
                    try { full = await GetAsync("https://management.azure.com" + id + "?api-version=" + v, ct); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "environment report: {Type} could not be read", type); }
                }
                resources.Add(Describe(r, full));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "environment report: resources"); error = "the resources could not be read: " + ex.Message; }
        try
        {
            var ra = await GetAsync(rg + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()", ct);
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var a in (ra?["value"] as JsonArray ?? new JsonArray()).OfType<JsonObject>())
            {
                var p = a["properties"];
                var defId = p?["roleDefinitionId"]?.GetValue<string>() ?? "";
                if (!names.TryGetValue(defId, out var name))
                {
                    try { name = (await GetAsync("https://management.azure.com" + defId + "?api-version=2022-04-01", ct))?["properties"]?["roleName"]?.GetValue<string>() ?? defId; }
                    catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "environment report: role name"); name = defId; }
                    names[defId] = name;
                }
                roles.Add(new AzureRoleAssignment(p?["principalId"]?.GetValue<string>() ?? "", p?["principalType"]?.GetValue<string>() ?? "", name, p?["scope"]?.GetValue<string>() ?? ""));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "environment report: role assignments"); error = (error is null ? "" : error + "; ") + "the role assignments could not be read: " + ex.Message; }
        return new AzureFacts(o.SubscriptionId, o.ResourceGroup, resources, roles, error);
    }

    /// PURE. The named facts of one resource (the list entry, and its full GET when there is one).
    public static AzureResource Describe(JsonObject listEntry, JsonNode? full)
    {
        var id = listEntry["id"]?.GetValue<string>() ?? "";
        var type = listEntry["type"]?.GetValue<string>() ?? "";
        var src = full ?? listEntry;
        var p = src["properties"];
        var net = new List<(string, string)>();
        void Add(string fact, JsonNode? n) { if (n is JsonValue v) net.Add((fact, v.ToString())); }
        switch (type.ToLowerInvariant())
        {
            case "microsoft.app/containerapps":
                Add("external ingress", p?["configuration"]?["ingress"]?["external"]);
                if (p?["configuration"]?["ingress"]?["ipSecurityRestrictions"] is JsonArray ips) net.Add(("IP restrictions", ips.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                else if (p?["configuration"]?["ingress"] is not null) net.Add(("IP restrictions", "0"));
                break;
            case "microsoft.sql/servers":
            case "microsoft.containerregistry/registries":
                Add("public network access", p?["publicNetworkAccess"]);
                break;
            case "microsoft.keyvault/vaults":
                Add("public network access", p?["publicNetworkAccess"]);
                Add("default network rule", p?["networkAcls"]?["defaultAction"]);
                break;
            case "microsoft.storage/storageaccounts":
                Add("public network access", p?["publicNetworkAccess"]);
                Add("default network rule", p?["networkAcls"]?["defaultAction"]);
                Add("anonymous blob access", p?["allowBlobPublicAccess"]);
                break;
        }
        var identity = src["identity"];
        var ua = (identity?["userAssignedIdentities"] as JsonObject)?.Select(kv => kv.Key.Split('/').Last()).ToList();
        return new AzureResource(id, listEntry["name"]?.GetValue<string>() ?? id.Split('/').Last(), type, listEntry["location"]?.GetValue<string>(), net,
            identity?["principalId"]?.GetValue<string>() ?? p?["principalId"]?.GetValue<string>(), ua, p?["clientId"]?.GetValue<string>());
    }
}
