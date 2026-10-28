using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using SI.Management.Web.ChangeJournal;

namespace SI.Management.Web.ConfigIo;

/// <summary>
/// PURE. Framework CONFIG-IO-1 (SI #490) -- THE EXPORT FILE IS THE BACKUP FILE: the signed configuration backup format of
/// CONFIG-1.3 (<see cref="ConfigBackupFile"/>: format, version, content, its SHA-256 and this installation's signature), with
/// the CONFIG-IO-1 header added -- product, version, schemaVersion, tenantId, environment, exportedUtc, exportedBy and the
/// chosen sections -- so an export imports on Backups (restore) and a backup file imports here. One section = one entity of
/// the configuration set (config\config-entities.locked.json). Never a secret VALUE: a secret setting holds only its Key
/// Vault secret's NAME and a connector only its secret references; the header lists each as "set" / "not set" with the name.
/// </summary>
public static class ConfigExport
{
    public const string Product = "SecurityInsight";
    /// The CONFIG-IO-1 schema of the file's header and sections; a file with a higher one is refused (it is newer).
    public const int SchemaVersion = 1;

    public sealed record Header(string? Version, string? TenantId, string? Environment, DateTime ExportedUtc, string ExportedBy);

    /// The sections an export can hold: every backed-up entity, in the catalog's order.
    public static IReadOnlyList<ConfigEntities.Entity> Sections(ConfigEntities entities) => entities.Backed.OrderBy(e => e.Order).ToList();

    /// The records of the chosen sections (all when none is chosen).
    public static IReadOnlyList<ConfigRecord> Pick(IReadOnlyList<ConfigRecord> records, IReadOnlyCollection<string> sections) =>
        sections.Count == 0 ? records : records.Where(r => sections.Contains(r.Entity, StringComparer.Ordinal)).ToList();

    /// The secrets the file refers to, by NAME: a secret setting's Key Vault secret name, a connector's secret references.
    public static JsonArray Secrets(IReadOnlyList<ConfigRecord> records)
    {
        var a = new JsonArray();
        foreach (var r in records.Where(r => r.Entity == "setting"))
        {
            var kv = ConfigEntities.Text(r.Record["KeyVaultSecretName"]);
            if (kv.Length > 0) a.Add(new JsonObject { ["section"] = "setting", ["item"] = r.Key, ["state"] = "set", ["secretName"] = kv });
        }
        foreach (var r in records.Where(r => r.Entity == "connector"))
        {
            var refs = ConfigEntities.Text(r.Record["SecretRefsJson"]);
            a.Add(new JsonObject { ["section"] = "connector", ["item"] = r.Key, ["state"] = refs.Length > 2 ? "set" : "not set", ["secretRefs"] = refs.Length > 2 ? refs : null });
        }
        return a;
    }

    /// The file, signed by this installation (the backup file's own signature).
    public static string Build(IReadOnlyList<ConfigRecord> records, IReadOnlyCollection<string> sections, Header h, IDataProtector protector)
    {
        var content = new JsonArray(records.Select(r => (JsonNode)new JsonObject { ["e"] = r.Entity, ["k"] = r.Key, ["r"] = r.Record.DeepClone() }).ToArray());
        var compact = content.ToJsonString();
        var hash = ConfigBackupFile.Sha256(compact);
        string T(DateTime d) => d.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        var chosen = sections.Count == 0 ? records.Select(r => r.Entity).Distinct().ToList() : sections.ToList();
        var o = new JsonObject
        {
            ["format"] = ConfigBackupFile.Format, ["version"] = ConfigBackupFile.Version,
            ["product"] = Product, ["schemaVersion"] = SchemaVersion, ["productVersion"] = h.Version,
            ["tenantId"] = h.TenantId, ["environment"] = h.Environment,
            ["backupId"] = 0, ["takenUtc"] = T(h.ExportedUtc), ["takenBy"] = h.ExportedBy,
            ["exportedUtc"] = T(h.ExportedUtc), ["exportedBy"] = h.ExportedBy,
            ["sections"] = new JsonArray(chosen.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
            ["secrets"] = Secrets(records),
            ["contentSha256"] = hash, ["signature"] = protector.Protect(hash), ["content"] = JsonNode.Parse(compact),
        };
        return o.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
}

/// <summary>
/// PURE. CONFIG-IO-1 import, select which: the file against the configuration in force now, per section and item --
/// NEW (in the file, not here: importing adds it), CHANGED (both, the content differs: importing sets it to the file's),
/// UNCHANGED, and ONLY HERE (here, not in the file: importing it would REMOVE it -- never ticked by default). A record that
/// carries tenant-specific ids (an Entra object id: access, department people, advisors) while the file comes from another
/// tenant (or does not say which) is FLAGGED and never ticked by default -- a person decides. The checks before anything:
/// the file's schema or product version newer than this one = refused; an entity this version does not know = refused.
/// </summary>
public static class ConfigImport
{
    public enum State { New, Changed, Unchanged, OnlyHere }

    public sealed record Item(ConfigDiff.Item? Diff, ConfigEntities.Entity Entity, string Key, State State, string? Flag)
    {
        public string Id => Entity.Name + "|" + Key;
        public bool DefaultTicked => State is State.New or State.Changed && Flag is null;
        public string Words => State switch
        {
            State.New => "new -- importing adds it",
            State.Changed => "changed -- importing sets it to the file's",
            State.OnlyHere => "only here -- importing it would REMOVE it",
            _ => "unchanged",
        };
    }

    public sealed record Section(ConfigEntities.Entity Entity, int New, int Changed, int Unchanged, int OnlyHere, int Flagged);

    public sealed record Plan(IReadOnlyList<Item> Items, IReadOnlyList<Section> Sections, IReadOnlyList<string> Refusals, IReadOnlyList<string> Warnings)
    {
        public bool Refused => Refusals.Count > 0;
    }

    private static readonly Regex Guid = new("[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly string[] IdColumns = ["PrincipalId", "ObjectId"];

    /// Compares "1.2.3" style versions (any "v" prefix and suffix after a space / dash / plus ignored); null when either is not a version.
    public static int? CompareVersions(string? a, string? b)
    {
        static System.Version? P(string? s)
        {
            var m = Regex.Match((s ?? "").Trim().TrimStart('v', 'V'), @"^\d+(\.\d+){1,3}", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            return m.Success && System.Version.TryParse(m.Value, out var v) ? v : null;
        }
        var va = P(a); var vb = P(b);
        return va is null || vb is null ? null : va.CompareTo(vb);
    }

    /// The tenant-specific ids a record carries (an object id column holding a GUID), or null.
    public static string? TenantIds(ConfigEntities.Entity e, JsonObject? record)
    {
        if (record is null) return null;
        foreach (var c in IdColumns.Where(e.Has))
            if (Guid.IsMatch(ConfigEntities.Text(record[c]))) return $"{c} is an Entra object id of the tenant it was exported from";
        return null;
    }

    public static Plan Build(JsonObject? header, IReadOnlyList<ConfigRecord> file, IReadOnlyList<ConfigRecord> now, ConfigEntities entities,
        IReadOnlyCollection<string> sections, string? thisVersion, string? thisTenantId)
    {
        var refusals = new List<string>();
        var warnings = new List<string>();
        var fileSchema = header?["schemaVersion"] is JsonValue sv && sv.TryGetValue<int>(out var s) ? s : (int?)null;
        if (fileSchema is { } fs && fs > ConfigExport.SchemaVersion) refusals.Add($"the file is newer (schema {fs}; this version reads up to {ConfigExport.SchemaVersion}) -- update SecurityInsight first");
        var fileVersion = ConfigEntities.Text(header?["productVersion"]);
        if (CompareVersions(fileVersion, thisVersion) is > 0) refusals.Add($"the file comes from a newer SecurityInsight ({fileVersion}; this is {thisVersion}) -- update SecurityInsight first");
        var product = ConfigEntities.Text(header?["product"]);
        if (product.Length > 0 && !product.Equals(ConfigExport.Product, StringComparison.OrdinalIgnoreCase)) refusals.Add($"the file is from {product}, not SecurityInsight");
        var unknown = file.Select(r => r.Entity).Distinct().Where(n => entities.Find(n) is not { Backup: true }).ToList();
        if (unknown.Count > 0) refusals.Add("the file holds sections this version does not know: " + string.Join(", ", unknown));
        var fileTenant = ConfigEntities.Text(header?["tenantId"]);
        var otherTenant = fileTenant.Length == 0 || thisTenantId is null || !fileTenant.Equals(thisTenantId, StringComparison.OrdinalIgnoreCase);
        if (fileTenant.Length == 0) warnings.Add("the file does not say which tenant it comes from: records with Entra object ids are flagged");
        else if (otherTenant) warnings.Add($"the file comes from another tenant ({fileTenant}): records with Entra object ids are flagged -- such an id means nothing here");
        if (fileSchema is null) warnings.Add("a backup file without the export header -- it is read as a backup of this format");
        if (refusals.Count > 0) return new Plan(Array.Empty<Item>(), Array.Empty<Section>(), refusals, warnings);

        var chosen = sections.Count == 0 ? entities.Backed.Select(e => e.Name).ToHashSet(StringComparer.Ordinal) : sections.ToHashSet(StringComparer.Ordinal);
        var fileIn = file.Where(r => chosen.Contains(r.Entity)).ToList();
        var nowIn = now.Where(r => chosen.Contains(r.Entity)).ToList();
        var diff = ConfigDiff.Compare(fileIn, nowIn, entities);
        var items = new List<Item>();
        foreach (var d in diff)
        {
            var st = d.Kind switch { ConfigDiff.Kind.RemovedSince => State.New, ConfigDiff.Kind.AddedSince => State.OnlyHere, _ => State.Changed };
            var flag = otherTenant && st != State.OnlyHere ? TenantIds(d.Entity, d.Backup) : null;
            items.Add(new Item(d, d.Entity, d.Key, st, flag));
        }
        var differing = diff.Select(d => (d.Entity.Name, d.Key)).ToHashSet();
        foreach (var r in fileIn.Where(r => !differing.Contains((r.Entity, r.Key))))
            if (entities.Find(r.Entity) is { } e) items.Add(new Item(null, e, r.Key, State.Unchanged, null));
        var sectionList = items.GroupBy(i => i.Entity).OrderBy(g => g.Key.Order).Select(g => new Section(g.Key,
            g.Count(i => i.State == State.New), g.Count(i => i.State == State.Changed), g.Count(i => i.State == State.Unchanged), g.Count(i => i.State == State.OnlyHere), g.Count(i => i.Flag is not null))).ToList();
        return new Plan(items.OrderBy(i => i.Entity.Order).ThenBy(i => i.State).ThenBy(i => i.Key, StringComparer.Ordinal).ToList(), sectionList, refusals, warnings);
    }
}
