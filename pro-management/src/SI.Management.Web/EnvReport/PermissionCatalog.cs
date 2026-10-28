using System.Text.Json;

namespace SI.Management.Web.EnvReport;

/// <summary>
/// config\permissions.locked.json, read by the web app -- THE ONE LIST of what each SecurityInsight identity must hold (the
/// engines check themselves against the same file at run start). Linked next to the app (catalog\); a source-tree run finds
/// it in config\ above. Areas use the engine's own words so a self-check's gap matches its line: the API's resource name
/// ("Microsoft Graph"), "Azure" and "Pro database".
/// </summary>
public sealed class PermissionCatalog
{
    public sealed record Item(string Area, string Name, string? When, string Why);

    public sealed record Identity(string Key, string Label, IReadOnlyList<Item> Items, IReadOnlyDictionary<string, string> Fixes)
    {
        public string? Fix(string area) => Fixes.TryGetValue(area switch { "Azure" => "azure", "Pro database" => "database", _ => "api" }, out var f) ? f : null;
    }

    public IReadOnlyList<Identity> Identities { get; }
    private readonly Dictionary<string, string> _engines;

    public PermissionCatalog(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var ids = new List<Identity>();
        foreach (var p in root.GetProperty("identities").EnumerateObject())
        {
            var v = p.Value;
            var label = v.TryGetProperty("label", out var l) ? l.GetString() ?? p.Name : p.Name;
            var items = new List<Item>();
            if (v.TryGetProperty("api", out var api))
                foreach (var a in api.EnumerateArray())
                {
                    var res = a.GetProperty("resource").GetString() ?? "API";
                    foreach (var r in a.GetProperty("roles").EnumerateArray()) items.Add(new Item(res, r.GetString() ?? "", null, $"read by the engines through {res}"));
                    if (a.TryGetProperty("conditionalRoles", out var cr))
                        foreach (var c in cr.EnumerateArray()) items.Add(new Item(res, c.GetProperty("role").GetString() ?? "", c.TryGetProperty("when", out var w) ? w.GetString() : null, $"written through {res} only while its setting is on"));
                }
            if (v.TryGetProperty("azure", out var az))
                foreach (var a in az.EnumerateArray())
                    items.Add(new Item("Azure", a.GetProperty("item").GetString() ?? "", a.TryGetProperty("when", out var w) ? w.GetString() : null,
                        "Azure action " + (a.TryGetProperty("action", out var act) ? act.GetString() : "")));
            if (v.TryGetProperty("database", out var db))
                foreach (var d in db.EnumerateArray()) items.Add(new Item("Pro database", d.GetString() ?? "", null, "the Pro database (records, CIs, configuration)"));
            var fixes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (v.TryGetProperty("fix", out var fx)) foreach (var f in fx.EnumerateObject()) fixes[f.Name] = f.Value.GetString() ?? "";
            ids.Add(new Identity(p.Name, label, items, fixes));
        }
        Identities = ids;
        _engines = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("engines", out var en))
            foreach (var e in en.EnumerateObject())
                if (e.Value.TryGetProperty("identity", out var i)) _engines[e.Name] = i.GetString() ?? "";
    }

    /// The identity key an engine runs as ("default" when it is not listed).
    public string IdentityOfEngine(string engine) =>
        _engines.TryGetValue(engine ?? "", out var i) ? i : _engines.TryGetValue("default", out var d) ? d : "collection";

    public const string FileName = "permissions.locked.json";

    public static string? Locate()
    {
        var linked = Path.Combine(AppContext.BaseDirectory, "catalog", FileName);
        if (File.Exists(linked)) return linked;
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "config", FileName);
            if (File.Exists(p)) return p;
        }
        return null;
    }

    private static readonly Lazy<PermissionCatalog?> Shipped = new(() => Locate() is { } p ? new PermissionCatalog(File.ReadAllText(p)) : null);
    /// The shipped list, or null when the file is not there (the report then says the permissions cannot be compared).
    public static PermissionCatalog? Default => Shipped.Value;
}
