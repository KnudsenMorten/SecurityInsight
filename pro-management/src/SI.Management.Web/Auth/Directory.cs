using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Azure.Core;

namespace SI.Management.Web.Auth;

/// Settings section "Access".
public sealed class AccessOptions
{
    public const string Section = "Access";
    /// Read group membership (when the token says "too many groups to list") and the names of users and groups from
    /// Microsoft Graph, as the web app's own identity. Needs the APPLICATION permission GroupMember.Read.All and
    /// User.ReadBasic.All on that identity -- granted by an administrator; setup does not grant it. Off by default: then
    /// groups come from the sign-in token only and a name is the one typed on the Access page.
    public bool GraphLookup { get; set; }
}

/// The groups a user is in, when the token could not list them. Null = unknown (not looked up or the lookup failed).
public interface IGroupMembershipSource
{
    Task<IReadOnlyList<string>?> GroupsOfAsync(string userObjectId, CancellationToken ct);
}

/// The display name of a user or group, for the Access page. Null = unknown (lookup off or failed).
public interface IDirectoryNames
{
    bool Enabled { get; }
    Task<(string Type, string Name)?> NameOfAsync(string objectId, CancellationToken ct);
    /// #335: a person typed into a department's people field -- a mail address (a user's mail or sign-in name) or an
    /// object id (a user or group) -- as the directory knows them. Null = unknown (lookup off, not found, or failed).
    Task<DirectoryPerson?> FindAsync(string mailOrObjectId, CancellationToken ct) => Task.FromResult<DirectoryPerson?>(null);
    /// #335: the people picker -- users and groups whose name, mail or sign-in name starts with the text typed (a few of
    /// each). Empty when the lookup is off or fails.
    Task<IReadOnlyList<DirectoryPerson>> SearchAsync(string text, CancellationToken ct) => Task.FromResult<IReadOnlyList<DirectoryPerson>>(Array.Empty<DirectoryPerson>());
    /// #446: who holds a role on the enterprise application of this web app (its client id) -- the app role assignments
    /// made in Entra (the installer, the named administrators). Null = unknown (lookup off or failed).
    Task<IReadOnlyList<AppRoleHolder>?> AppRoleHoldersAsync(string clientId, CancellationToken ct) => Task.FromResult<IReadOnlyList<AppRoleHolder>?>(null);
}

/// A user or group found in the directory: Type "user" | "group", its object id, name and mail (null when it has none);
/// Guest = a B2B guest user (#765: guests are found and added like members).
public sealed record DirectoryPerson(string Type, string ObjectId, string Name, string? Mail, bool Guest = false);

/// #446: one app role assignment on the web app's enterprise application: who (User | Group | ServicePrincipal), and the
/// role's value (SuperAdmin, Admin, Viewer, Wallboard, Department).
public sealed record AppRoleHolder(string ObjectId, string Type, string Name, string Role);

/// The default: no directory reads at all. Groups come only from the `groups` claim of the sign-in token.
public sealed class NoDirectoryLookup : IGroupMembershipSource, IDirectoryNames
{
    public bool Enabled => false;
    public Task<IReadOnlyList<string>?> GroupsOfAsync(string userObjectId, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>?>(null);
    public Task<(string Type, string Name)?> NameOfAsync(string objectId, CancellationToken ct) => Task.FromResult<(string, string)?>(null);
}

/// <summary>
/// Microsoft Graph as the app's own identity (Access:GraphLookup = true). Transitive group membership through
/// <c>POST /users/{id}/getMemberGroups</c>; names through <c>GET /directoryObjects/{id}</c>. Any failure answers
/// "unknown" -- it never raises anyone, and the sign-in still works with the token's own information.
/// </summary>
public sealed class GraphDirectory : IGroupMembershipSource, IDirectoryNames
{
    private const string Graph = "https://graph.microsoft.com/v1.0";
    private static readonly string[] Scope = ["https://graph.microsoft.com/.default"];
    private readonly HttpClient _http;
    private readonly TokenCredential _credential;
    private readonly ILogger<GraphDirectory> _log;

    public GraphDirectory(HttpClient http, TokenCredential credential, ILogger<GraphDirectory> log) { _http = http; _credential = credential; _log = log; }

    public bool Enabled => true;

    private async Task<HttpRequestMessage> Request(HttpMethod m, string url, CancellationToken ct)
    {
        var token = await _credential.GetTokenAsync(new TokenRequestContext(Scope), ct);
        var r = new HttpRequestMessage(m, url);
        r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        return r;
    }

    public async Task<IReadOnlyList<string>?> GroupsOfAsync(string userObjectId, CancellationToken ct)
    {
        if (!SqlAccessStore.ObjectId().IsMatch(userObjectId)) return null;
        try
        {
            using var req = await Request(HttpMethod.Post, $"{Graph}/users/{userObjectId}/getMemberGroups", ct);
            req.Content = JsonContent.Create(new { securityEnabledOnly = false });
            using var res = await _http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) { _log.LogWarning("group membership lookup answered {Status}", (int)res.StatusCode); return null; }
            using var d = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return d.RootElement.GetProperty("value").EnumerateArray().Select(v => v.GetString() ?? "").Where(v => v.Length > 0).ToList();
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or KeyNotFoundException or InvalidOperationException or Azure.Identity.AuthenticationFailedException)
        {
            _log.LogWarning(ex, "group membership could not be read from Microsoft Graph");
            return null;
        }
    }

    public async Task<(string Type, string Name)?> NameOfAsync(string objectId, CancellationToken ct)
    {
        if (!SqlAccessStore.ObjectId().IsMatch(objectId)) return null;
        try
        {
            using var req = await Request(HttpMethod.Get, $"{Graph}/directoryObjects/{objectId}", ct);
            using var res = await _http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            using var d = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var odata = d.RootElement.TryGetProperty("@odata.type", out var t) ? t.GetString() ?? "" : "";
            var name = d.RootElement.TryGetProperty("displayName", out var n) ? n.GetString() ?? "" : "";
            var type = odata.EndsWith("group", StringComparison.OrdinalIgnoreCase) ? AccessAssignment.Group
                : odata.EndsWith("user", StringComparison.OrdinalIgnoreCase) ? AccessAssignment.User : "";
            return type.Length == 0 || name.Length == 0 ? null : (type, name);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidOperationException or Azure.Identity.AuthenticationFailedException)
        {
            _log.LogWarning(ex, "a name could not be read from Microsoft Graph");
            return null;
        }
    }

    /// <summary>
    /// #765: the users' filter of the people picker -- members AND B2B guests (GET /users lists both): the name, the mail
    /// (a guest's real address) or the sign-in name (a guest's is name_domain#EXT#@tenant) starting with the text. A text
    /// that is a guest's home address (anna@contoso.com) also finds the guest by the start of the sign-in name Entra made of
    /// it (anna_contoso.com#EXT#...). Null = nothing to search.
    /// </summary>
    public static string? UserSearchFilter(string? text)
    {
        var t = (text ?? "").Trim();
        if (t.Length < 2 || t.Length > 100 || t.Any(char.IsControl)) return null;
        var v = t.Replace("'", "''", StringComparison.Ordinal);
        var f = $"startswith(displayName,'{v}') or startswith(mail,'{v}') or startswith(userPrincipalName,'{v}')";
        var at = v.LastIndexOf('@');
        if (at > 0 && at < v.Length - 1 && !v.Contains("#EXT#", StringComparison.OrdinalIgnoreCase))
            f += $" or startswith(userPrincipalName,'{v[..at]}_{v[(at + 1)..]}#EXT#')";
        return f;
    }

    /// Users -- members and guests (name, mail or sign-in name starting with the text) -- and groups (name starting with
    /// it), up to 8 of each.
    public async Task<IReadOnlyList<DirectoryPerson>> SearchAsync(string text, CancellationToken ct)
    {
        var userFilter = UserSearchFilter(text);
        if (userFilter is null) return Array.Empty<DirectoryPerson>();
        var v = (text ?? "").Trim().Replace("'", "''", StringComparison.Ordinal);
        var found = new List<DirectoryPerson>();
        async Task Read(string url, string type)
        {
            try
            {
                using var req = await Request(HttpMethod.Get, url, ct);
                using var res = await _http.SendAsync(req, ct);
                if (!res.IsSuccessStatusCode) { _log.LogWarning("the people search answered {Status}", (int)res.StatusCode); return; }
                using var d = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                foreach (var e in d.RootElement.GetProperty("value").EnumerateArray())
                {
                    string? S(string p) => e.TryGetProperty(p, out var x) && x.ValueKind == JsonValueKind.String ? x.GetString() : null;
                    if (S("id") is not { } id) continue;
                    var guest = type == "user" && (string.Equals(S("userType"), "Guest", StringComparison.OrdinalIgnoreCase) || (S("userPrincipalName") ?? "").Contains("#EXT#", StringComparison.OrdinalIgnoreCase));
                    found.Add(new DirectoryPerson(type, id.ToLowerInvariant(), S("displayName") ?? S("mail") ?? id, S("mail") ?? (type == "user" ? S("userPrincipalName") : null), guest));
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or JsonException or KeyNotFoundException or InvalidOperationException or Azure.Identity.AuthenticationFailedException)
            {
                _log.LogWarning(ex, "the people search could not read Microsoft Graph");
            }
        }
        // userType is not part of the basic profile (User.ReadBasic.All): a guest is known by the #EXT# of its sign-in name
        await Read($"{Graph}/users?$select=id,displayName,mail,userPrincipalName&$top=8&$filter=" + Uri.EscapeDataString(userFilter), "user");
        await Read($"{Graph}/groups?$select=id,displayName,mail&$top=8&$filter=" + Uri.EscapeDataString($"startswith(displayName,'{v}')"), "group");
        return found;
    }

    /// #446: the enterprise application's app role assignments (GET /servicePrincipals?$filter=appId eq ... then
    /// /servicePrincipals/{id}/appRoleAssignedTo) -- needs Application.Read.All on the web app's identity. Any failure: null.
    public async Task<IReadOnlyList<AppRoleHolder>?> AppRoleHoldersAsync(string clientId, CancellationToken ct)
    {
        if (!Guid.TryParse(clientId, out var appId)) return null;
        try
        {
            using var spReq = await Request(HttpMethod.Get, $"{Graph}/servicePrincipals?$select=id,appRoles&$filter=" + Uri.EscapeDataString($"appId eq '{appId}'"), ct);
            using var spRes = await _http.SendAsync(spReq, ct);
            if (!spRes.IsSuccessStatusCode) { _log.LogWarning("the enterprise application could not be read ({Status})", (int)spRes.StatusCode); return null; }
            using var spDoc = JsonDocument.Parse(await spRes.Content.ReadAsStringAsync(ct));
            var sps = spDoc.RootElement.GetProperty("value");
            if (sps.GetArrayLength() != 1) return null;
            var sp = sps[0];
            var spId = sp.GetProperty("id").GetString();
            var roles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (sp.TryGetProperty("appRoles", out var ar))
                foreach (var r in ar.EnumerateArray())
                    if (r.TryGetProperty("id", out var rid) && r.TryGetProperty("value", out var rv) && rid.GetString() is { } k && rv.GetString() is { } v) roles[k] = v;
            using var req = await Request(HttpMethod.Get, $"{Graph}/servicePrincipals/{spId}/appRoleAssignedTo?$top=999", ct);
            using var res = await _http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) { _log.LogWarning("the app role assignments could not be read ({Status})", (int)res.StatusCode); return null; }
            using var d = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var list = new List<AppRoleHolder>();
            foreach (var e in d.RootElement.GetProperty("value").EnumerateArray())
            {
                string? S(string p) => e.TryGetProperty(p, out var x) && x.ValueKind == JsonValueKind.String ? x.GetString() : null;
                if (S("principalId") is not { } pid || S("appRoleId") is not { } role || !roles.TryGetValue(role, out var value)) continue;
                list.Add(new AppRoleHolder(pid.ToLowerInvariant(), S("principalType") ?? "User", S("principalDisplayName") ?? pid, value));
            }
            return list;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or KeyNotFoundException or InvalidOperationException or Azure.Identity.AuthenticationFailedException)
        {
            _log.LogWarning(ex, "the app role holders could not be read from Microsoft Graph");
            return null;
        }
    }

    /// An object id: GET /directoryObjects/{id}; a mail address: the user whose mail or sign-in name it is (exactly one).
    public async Task<DirectoryPerson?> FindAsync(string mailOrObjectId, CancellationToken ct)
    {
        var q = (mailOrObjectId ?? "").Trim();
        string url;
        if (SqlAccessStore.ObjectId().IsMatch(q)) url = $"{Graph}/directoryObjects/{q}?$select=id,displayName,mail,userPrincipalName";
        else if (SI.Management.Web.Departments.DepartmentPeople.IsMail(q))
        {
            var v = q.Replace("'", "''", StringComparison.Ordinal);
            url = $"{Graph}/users?$select=id,displayName,mail,userPrincipalName&$top=2&$filter=" + Uri.EscapeDataString($"mail eq '{v}' or userPrincipalName eq '{v}'");
        }
        else return null;
        try
        {
            using var req = await Request(HttpMethod.Get, url, ct);
            using var res = await _http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            using var d = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var root = d.RootElement;
            if (root.TryGetProperty("value", out var list))
            {
                if (list.GetArrayLength() != 1) return null;
                root = list[0];
            }
            string? S(string p) => root.TryGetProperty(p, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
            var odata = S("@odata.type") ?? "#microsoft.graph.user";
            var type = odata.EndsWith("group", StringComparison.OrdinalIgnoreCase) ? "group" : odata.EndsWith("user", StringComparison.OrdinalIgnoreCase) ? "user" : "";
            var id = S("id");
            if (type.Length == 0 || id is null) return null;
            return new DirectoryPerson(type, id.ToLowerInvariant(), S("displayName") ?? S("mail") ?? id, S("mail") ?? (type == "user" ? S("userPrincipalName") : null));
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidOperationException or Azure.Identity.AuthenticationFailedException)
        {
            _log.LogWarning(ex, "a person could not be looked up in Microsoft Graph");
            return null;
        }
    }
}
