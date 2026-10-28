using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SI.Management.Web.Data;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// What a pack (or a roll-back) covers: an installed item outside the scope is never retired by it.
public sealed record PackScope(bool Full, IReadOnlyList<string> Kinds, IReadOnlyList<string> Methods, IReadOnlyList<string> Items, IReadOnlyList<string>? Classes = null)
{
    public static readonly PackScope Everything = new(true, TemplateConformance.TemplatedKinds, Array.Empty<string>(), Array.Empty<string>());
    /// #405: a scope that names classes (a Microsoft content pack, a roll back of one class) covers only items of them.
    public bool HasClasses => Classes is { Count: > 0 };
    public bool Covers(string kind, string name, string methodId, string? cls = null) =>
        (!HasClasses || (cls is not null && Classes!.Contains(cls, StringComparer.Ordinal))) &&
        (Kinds.Count == 0 || Kinds.Contains(kind, StringComparer.Ordinal)) &&
        (Methods.Count == 0 || Methods.Contains(methodId, StringComparer.Ordinal)) &&
        (Items.Count == 0 || Items.Contains(name, StringComparer.Ordinal));
}

/// One item a release would put in force (a pack item, or a roll-back's revision).
public sealed record CandidateItem(string Kind, string ItemKey, string MethodId, string ContentHash, string Body, string Format, string Version)
{
    public string Name => Kind + "/" + ItemKey;
}

/// One installed template (cfg.Template, live or retired).
public sealed record InstalledTemplate(string Kind, string ItemKey, string? Version, string? ContentHash, string? Body, string Format, string? Source, DateTime? RetiredAt, int SortOrder = 0)
{
    public string Name => Kind + "/" + ItemKey;
    public string MethodId => TemplateMethods.Of(Kind, ItemKey, Source, Body).Id;
}

/// A staged template pack, parsed and checked against the SHA-256 it was staged with.
public sealed record TemplatePack(string PackVersion, string CodeVersion, string? Commit, PackScope Scope, string Fingerprint, IReadOnlyList<CandidateItem> Items, string Sha256, string? Name = null,
    // #405: 'microsoft' = a Microsoft content pack; the oldest code that may install it
    string? Content = null, string? MinCodeVersion = null)
{
    public bool IsMicrosoftContent => Content == TemplateClasses.Microsoft;
}

/// <summary>
/// #405 -- what is installed PER CLASS, in the page's words: the code release whose fix + default templates are in force
/// (cfg.InstallState TemplateCode), the Microsoft content pack (TemplatePack) and how it came (automatically, with the code,
/// released by hand), ring 1's direct install (TemplateDirect), the pack the customer rolled back from (TemplatePackDeclined),
/// the install mode (TemplateMode: split | gated) and the customer's "Hold template packs" setting.
/// </summary>
public sealed record TemplateInstallSummary(bool Split, string? CodeVersion, DateTime? CodeAt, string? MicrosoftPack, DateTime? MicrosoftAt, string? MicrosoftHow,
    string? DirectVersion, DateTime? DirectAt, string? Declined, bool Hold)
{
    public static TemplateInstallSummary From(IReadOnlyDictionary<string, InstallStateRow> state, IReadOnlyList<ReleaseHistoryRow> history, bool hold)
    {
        string? V(string n) => state.TryGetValue(n, out var r) && !string.IsNullOrWhiteSpace(r.Value) ? r.Value.Trim() : null;
        DateTime? At(string n) => state.TryGetValue(n, out var r) ? r.UpdatedAt : null;
        var split = string.Equals(V("TemplateMode"), "split", StringComparison.Ordinal);
        var pack = V("TemplatePack");
        // how the Microsoft content in force came: the newest verified release record of that pack
        var rec = pack is null ? null : history.Where(h => h.Kind == "released" && h.Pack == pack).OrderByDescending(h => h.ChangeId).FirstOrDefault();
        var how = rec?.Mode switch { "auto" => "installed automatically", "code" or "shipped" or "adopted" => "installed with SecurityInsight " + (rec.Code ?? V("TemplateCode") ?? ""), "direct" => "installed directly (ring 1)", "rollback" => "rolled back to", "release" => "installed by hand", _ => null };
        return new TemplateInstallSummary(split, V("TemplateCode"), At("TemplateCode"), pack, rec?.ChangedAt ?? At("TemplatePack"), how?.Trim(), V("TemplateDirect"), At("TemplateDirect"), V("TemplatePackDeclined"), hold);
    }

    /// <summary>
    /// Owner decision 2026-10-11: ring 1 installs the current templates directly on every deploy, and that deploy stages
    /// the pack shipped with the code (origin 'shipped'). The pack in force there is therefore the newest shipped pack --
    /// also before the next deploy has recorded it as TemplatePack (Publish-SITemplates -InstallCurrent now does) -- so a
    /// pack whose content is already in force reads installed: no badge, no Install button.
    /// </summary>
    public TemplateInstallSummary WithStaged(IReadOnlyList<StagedPackInfo> staged)
    {
        if (DirectVersion is null) return this;
        var shipped = staged.Where(s => s.Origin == "shipped" && TemplateReleases.IsPackVersion(s.PackVersion))
                            .OrderByDescending(s => s.PackVersion, Comparer<string>.Create(TemplateReleases.CompareVersions)).FirstOrDefault();
        if (shipped is null || (MicrosoftPack is not null && TemplateReleases.CompareVersions(shipped.PackVersion, MicrosoftPack) <= 0)) return this;
        return this with { MicrosoftPack = shipped.PackVersion, MicrosoftHow = "installed directly (ring 1)", MicrosoftAt = DirectAt ?? MicrosoftAt };
    }
}

public sealed record ReleaseDiffItem(string Kind, string ItemKey, string MethodId, string Change, string? OldHash, string? NewHash, string? Override, string Format, string? OldBody, string? NewBody)
{
    public string Name => Kind + "/" + ItemKey;
    public bool Affected => Change != TemplateReleases.Unchanged && Override is "override" or "disable";
}

public sealed record MethodSummary(string Id, int Added, int Changed, int Retired, int Unchanged, int Affected)
{
    public string Engine => Id[..Id.IndexOf('/')];
    public string Method => Id[(Id.IndexOf('/') + 1)..];
    public bool HasChanges => Added + Changed + Retired > 0;
}

public sealed record ReleaseDiff(IReadOnlyList<ReleaseDiffItem> Items, IReadOnlyList<MethodSummary> Methods)
{
    /// Get-SIProSelectionFingerprint: over the selected methods' items (null or "*" = every method).
    public string Fingerprint(IReadOnlyCollection<string>? methods) => TemplateReleases.SelectionFingerprint(this, methods);
}

public sealed record StagedPackInfo(string PackVersion, string CodeVersion, string Sha256, string Fingerprint, string? Ring, string Origin, bool IsFull, int ItemCount, DateTime? StagedAt, string? StagedBy, string? Name = null,
    string? Content = null, string? MinCodeVersion = null)
{
    /// What the page calls the pack: its own name ("Default templates 1.0"), else "Template pack 1.1".
    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? "Template pack " + PackVersion : Name!;
    public bool IsMicrosoftContent => Content == TemplateClasses.Microsoft;
}

/// #405 + owner decision 2026-10-11 ("Automatic"): where a staged template pack stands -- Get-SIProTemplatePackDecision
/// (engine\pro-settings\SI-TemplatePacks.ps1) in the page's words (the job decides; this only says what it will do).
/// EVERY pack installs automatically, also one that carries more than Microsoft content; only the customer's Hold or a
/// roll back from the pack makes it wait for an Admin (Held -- the only state the nav badge counts). A shared case file
/// (tests\fixtures\template-pack-decision-cases.json) runs both.
public sealed record TemplatePackState(string State, string Text, bool CanInstall)
{
    public const string Installed = "installed", Waiting = "waiting", Held = "held", Automatic = "automatic";

    public static TemplatePackState Of(StagedPackInfo s, TemplateInstallSummary sum)
    {
        if (sum.MicrosoftPack is not null && TemplateReleases.CompareVersions(s.PackVersion, sum.MicrosoftPack) <= 0)
            return new(Installed, s.PackVersion == sum.MicrosoftPack ? "installed" : "older than the content in force", false);
        // the pack's MinCodeVersion; a pack without one that carries more than Microsoft content needs the code it was built by
        var min = !string.IsNullOrWhiteSpace(s.MinCodeVersion) ? s.MinCodeVersion : !s.IsMicrosoftContent && !string.IsNullOrWhiteSpace(s.CodeVersion) ? s.CodeVersion : null;
        // the code this install runs (unknown = the job decides; the page does not guess a wait)
        var code = sum.CodeVersion ?? sum.DirectVersion;
        if (min is not null && code is not null && TemplateReleases.CompareVersions(min, code) > 0)
            return new(Waiting, $"waits for SecurityInsight {min} (this install runs {code})", false);
        if (sum.Declined is not null && TemplateReleases.CompareVersions(s.PackVersion, sum.Declined) <= 0)
            return new(Held, $"you rolled back from {sum.Declined} -- not installed automatically", true);
        if (sum.Hold) return new(Held, "held: Hold template packs is on", true);
        return new(Automatic, "installed automatically at the next updater run", false);
    }
}

/// What is installed (cfg.InstallState 'TemplatePack' + 'TemplatePackStatus'), in the page's words.
public sealed record InstalledPack(string Version, string Name, bool Customised)
{
    public const string StatusCustomised = "customised";

    public string Describe => Customised ? $"{Name} -- customised, based on {Version}: your templates differ from it" : Name;

    /// null when no pack is recorded. The name is the staged pack's own (setup stages the shipped one), else "Template pack v".
    public static InstalledPack? From(IReadOnlyDictionary<string, InstallStateRow> state, IReadOnlyList<StagedPackInfo> staged)
    {
        if (!state.TryGetValue("TemplatePack", out var p) || string.IsNullOrWhiteSpace(p.Value)) return null;
        var v = p.Value.Trim();
        var name = staged.FirstOrDefault(s => s.PackVersion == v)?.Name;
        var customised = state.TryGetValue("TemplatePackStatus", out var st) && string.Equals(st.Value?.Trim(), StatusCustomised, StringComparison.OrdinalIgnoreCase);
        return new InstalledPack(v, string.IsNullOrWhiteSpace(name) ? "Template pack " + v : name!, customised);
    }
}

public sealed record InstallStateRow(string Name, string Value, string? Version, DateTime? UpdatedAt, string? UpdatedBy);

public sealed record ReleaseHistoryRow(long ChangeId, string Kind, string? NewValue, DateTime? ChangedAt, string? ChangedBy, string? Reason)
{
    private JsonNode? Json => NewValue is { Length: > 1 } v && v.TrimStart().StartsWith('{') ? TryParse(v) : null;
    private static JsonNode? TryParse(string v) { try { return JsonNode.Parse(v); } catch (JsonException) { return null; } }
    public string? Mode => (string?)Json?["Mode"];
    public string? Pack => (string?)Json?["Pack"];
    public string Methods => Json?["Methods"] is JsonArray a ? string.Join(", ", a.Select(x => (string?)x)) : "";
    public string? Selection => (string?)Json?["Selection"];
    public string? Execution => (string?)Json?["Execution"];
    /// #405: the code release a 'code' / 'direct' record belongs to
    public string? Code => (string?)Json?["Code"];

    /// What the History table says for the row.
    public string What => Kind switch
    {
        "released" => Mode switch
        {
            "rollback" => "rolled back (verified)",
            "auto" => "template pack installed automatically",
            "code" => "installed with SecurityInsight " + Code,
            "direct" => "installed directly, ring 1 (SecurityInsight " + Code + ")",
            _ => "released (verified)",
        },
        "requested" => Mode == "rollback" ? "roll back accepted" : "release accepted",
        "pack-staged" => "pack staged",
        _ => Kind,
    };
}

/// The detection method an item belongs to -- Get-SIProTemplateMethod (engine\pro-settings\SI-TemplatePacks.ps1), rule
/// for rule (a test runs both on the same fixture).
public static partial class TemplateMethods
{
    [GeneratedRegex("[^A-Za-z0-9_\\-]")] private static partial Regex NotName();

    private static string Clean(string? s) { var c = NotName().Replace(s ?? "", ""); return c.Length > 0 ? c : "Other"; }

    public static (string Engine, string Method, string Id) Of(string kind, string itemKey, string? source, string? body)
    {
        string engine = "config", method;
        switch (kind)
        {
            case "rule":
                var m = Regex.Match(itemKey ?? "", "^([a-z]+)/", RegexOptions.IgnoreCase);   // PowerShell's -match ignores case
                engine = m.Success ? m.Groups[1].Value : "shared";
                var parts = (source ?? "").Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
                method = parts.Length >= 3
                    ? Clean(Regex.Replace(Regex.Replace(parts[2], "\\.locked\\.yaml$", "", RegexOptions.IgnoreCase), "\\.ya?ml$", "", RegexOptions.IgnoreCase))
                    : "Other";
                break;
            case "rareport":
                engine = "riskanalysis";
                if ((itemKey ?? "").StartsWith("template/", StringComparison.Ordinal)) method = "ReportTemplates";
                else
                {
                    string? dom = null;
                    try { if (JsonNode.Parse(body ?? "") is JsonObject o && o["SecurityDomain"] is JsonValue v) dom = v.ToString(); }
                    catch (JsonException) { }
                    method = Clean(dom);
                }
                break;
            case "riskindex": engine = "riskanalysis"; method = "RiskIndex"; break;
            case "assettagging": engine = "endpoint"; method = "AssetTagging"; break;
            case "cmdbownership": method = "CmdbOwnership"; break;
            case "servicemodel": method = "ServiceModel"; break;
            // #456: one method per data-model template file (datamodel/field-catalog, datamodel/mappings-mde, ...)
            case "datamodel": { engine = "datamodel"; var n = itemKey ?? ""; var ci = n.IndexOf(':'); if (ci >= 0) n = n[..ci]; method = Clean(n.Replace('/', '-')); break; }
            case "naming": method = "Naming"; break;
            default: method = Clean(kind); break;
        }
        return (engine, method, engine + "/" + method);
    }
}

/// <summary>
/// TEMPLATE RELEASES (#235) -- the customer side of template versions released per ring. Reads the packs the updater (or
/// the publisher) staged in cfg.TemplatePackStaged, compares one with the templates in force PER DETECTION METHOD (new /
/// changed / retired rules, and the customer's overrides affected), and -- after an Admin committed a release or a roll
/// back on Review &amp; commit -- starts the Container Apps job caj-si-templates with the EXACT selection fingerprint the
/// Admin accepted. The job (setup\Publish-SITemplates.ps1 -Apply -AcceptFingerprint) refuses any other, writes, reads
/// back and only then records the release. This class never writes a template itself.
/// The diff and the fingerprint are the PowerShell module's (SI-TemplatePacks.ps1); content hashes are computed there
/// at publish -- this class only compares them.
/// </summary>
public sealed class TemplateReleases
{
    public const string Added = "added", Changed = "changed", Retired = "retired", Unchanged = "unchanged";
    public const string LogName = "template-release";
    public const string AllMethods = "*";

    public const string SchemaSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.TemplatePackStaged') IS NULL THEN 0 ELSE 1 END AS HasPackStaged,
       CASE WHEN COL_LENGTH(N'cfg.Template', N'ContentHash') IS NULL OR OBJECT_ID(N'cfg.TemplateRevision') IS NULL OR OBJECT_ID(N'cfg.InstallState') IS NULL OR OBJECT_ID(N'cfg.ItemOverride') IS NULL THEN 0 ELSE 1 END AS HasVersioning;
""";

    public const string StagedListSql = """
SELECT PackVersion, CodeVersion, Sha256, Fingerprint, Ring, Origin, IsFull, ItemCount, StagedAt, StagedBy, JSON_VALUE(PackJson, '$.Name') AS PackName,
       JSON_VALUE(PackJson, '$.Content') AS PackContent, JSON_VALUE(PackJson, '$.MinCodeVersion') AS MinCodeVersion FROM cfg.TemplatePackStaged;
""";

    public const string StagedPackSql = """
SELECT PackVersion, Sha256, PackJson FROM cfg.TemplatePackStaged WHERE PackVersion = @Pack;
""";

    /// Sent only when SchemaSql says the versioning schema is there (ContentHash would not compile otherwise).
    public const string TemplatesSql = """
SELECT Kind, ItemKey, [Version], ContentHash, BodyJson, Format, Source, RetiredAt, SortOrder FROM cfg.Template WHERE Kind NOT IN (N'naming', N'cmdbownership');
""";

    public const string OverridesSql = """
SELECT Kind, ItemKey, State FROM cfg.ItemOverride WHERE Kind NOT IN (N'naming', N'cmdbownership');
""";

    public const string InstallSql = """
SELECT Name, Value, [Version], UpdatedAt, UpdatedBy FROM cfg.InstallState WHERE Name IN (N'TemplatePack', N'TemplatePackStatus', N'TemplateFingerprint', N'TemplateCode', N'TemplateDirect', N'TemplatePackDeclined', N'TemplateMode');
""";

    /// #405: the customer's "Hold Microsoft content" setting (the Pro settings catalog, cfg.Setting scope 'solution').
    public const string HoldSettingName = "SI_InvardiaUpdate_HoldMicrosoftContent";
    public const string HoldSql = """
SELECT ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name = N'SI_InvardiaUpdate_HoldMicrosoftContent';
""";

    public const string HistorySql = """
SELECT TOP (50) ChangeId, Kind, NewValue, ChangedAt, ChangedBy, Reason FROM cfg.ChangeLog WHERE Name = N'template-release' ORDER BY ChangeId DESC;
""";

    public const string RevisionsSql = """
SELECT Kind, ItemKey, ContentHash, [Version], BodyJson, Format FROM cfg.TemplateRevision WHERE Kind NOT IN (N'naming', N'cmdbownership');
""";

    /// The Admin's request, written after the job started: who accepted what (the release itself is recorded by the job
    /// after its read-back). One row; the actor (@By) is the signed-in identity.
    public const string RequestSql = """
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'template-release', N'install', N'requested', N'Set', NULL, @Value, @By, @Reason);
SELECT N'Saved' AS Outcome;
""";

    /// Plain status, never a command: every setup and update path creates the schema and installs the default templates (#250).
    public const string MissingSchemaMessage = "Templates are being prepared -- the next update or setup run installs them.";
    public const string NoPackMessage = "No template pack is available yet -- the next update or setup run installs the default templates (1.0).";
    public const string NoInstalledMessage = "No template pack is recorded yet -- the next update or setup run installs the default templates.";
    public const string JobMissingMessage = "The release job is being prepared -- the next update or setup run adds it.";

    private static readonly Regex Sha = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex Version = new("^\\d{1,6}(\\.\\d{1,12}){1,5}$", RegexOptions.CultureInvariant);
    private static readonly Regex MethodIdRx = new("^[a-z]{1,20}/[A-Za-z0-9_\\-]{1,100}$", RegexOptions.CultureInvariant);

    private readonly ISqlExecutor _sql;
    private readonly IJobsClient _jobs;
    private readonly JobsOptions _jobOptions;

    public TemplateReleases(ISqlExecutor sql, IJobsClient jobs, IOptions<JobsOptions> jobOptions) { _sql = sql; _jobs = jobs; _jobOptions = jobOptions.Value; }

    public string JobName => string.IsNullOrWhiteSpace(_jobOptions.TemplatesJob) ? "caj-si-templates" : _jobOptions.TemplatesJob;
    public bool JobsConfigured => _jobs.IsConfigured;

    public static bool IsPackVersion(string? v) => v is { Length: <= 32 } && Version.IsMatch(v);
    public static bool IsMethodId(string? m) => m is not null && MethodIdRx.IsMatch(m);

    /// Compare-SIProPackVersion: numeric per part, 64-bit, a missing part is 0.
    public static int CompareVersions(string? a, string? b)
    {
        var pa = (a ?? "").Split('.', StringSplitOptions.RemoveEmptyEntries); var pb = (b ?? "").Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            long x = 0, y = 0;
            if (i < pa.Length) long.TryParse(pa[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out x);
            if (i < pb.Length) long.TryParse(pb[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out y);
            if (x != y) return x < y ? -1 : 1;
        }
        return 0;
    }

    public static string TextSha256(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    // ------------------------------------------------------------------------------------------------- reads

    /// (cfg.TemplatePackStaged exists, the versioning schema exists)
    public async Task<(bool PackTable, bool Versioning)> SchemaAsync(CancellationToken ct)
    {
        var r = (await _sql.QueryAsync(SchemaSql, new Dictionary<string, object?>(), ct)).FirstOrDefault();
        return (r?.Long("HasPackStaged") == 1, r?.Long("HasVersioning") == 1);
    }

    public async Task<IReadOnlyList<StagedPackInfo>> StagedAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(StagedListSql, new Dictionary<string, object?>(), ct))
            .Select(r => new StagedPackInfo(r.Str("PackVersion") ?? "", r.Str("CodeVersion") ?? "", (r.Str("Sha256") ?? "").Trim(), (r.Str("Fingerprint") ?? "").Trim(),
                r.Str("Ring"), r.Str("Origin") ?? "", r.Long("IsFull") == 1 || string.Equals(r.Str("IsFull"), "True", StringComparison.OrdinalIgnoreCase),
                (int)(r.Long("ItemCount") ?? 0), r.Date("StagedAt"), r.Str("StagedBy"), r.Str("PackName"), r.Str("PackContent"), r.Str("MinCodeVersion")))
            .OrderByDescending(p => p.PackVersion, Comparer<string>.Create(CompareVersions)).ToList();

    /// One staged pack, checked: its text must still match the SHA-256 it was staged with, and be a pack.
    public async Task<TemplatePack> PackAsync(string packVersion, CancellationToken ct)
    {
        if (!IsPackVersion(packVersion)) throw new ArgumentException($"'{packVersion}' is not a template pack version");
        var r = (await _sql.QueryAsync(StagedPackSql, new Dictionary<string, object?> { ["Pack"] = packVersion }, ct)).FirstOrDefault()
                ?? throw new InvalidOperationException($"template pack {packVersion} is not staged on this install");
        return ParsePack(r.Str("PackJson") ?? "", (r.Str("Sha256") ?? "").Trim());
    }

    public static TemplatePack ParsePack(string text, string expectedSha256)
    {
        var sha = TextSha256(text);
        if (!string.Equals(sha, expectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("the staged template pack does not match the SHA-256 it was staged with -- it was changed in the database; it cannot be released");
        var o = JsonNode.Parse(text) as JsonObject ?? throw new InvalidOperationException("the staged template pack is not a JSON object");
        if ((int?)o["Schema"] != 1) throw new InvalidOperationException("not a SecurityInsight template pack");
        var v = (string?)o["PackVersion"] ?? "";
        if (!IsPackVersion(v)) throw new InvalidOperationException($"the pack's version '{v}' is not a pack version");
        static IReadOnlyList<string> Strs(JsonNode? n) => n is JsonArray a ? a.Select(x => (string?)x ?? "").Where(x => x.Length > 0).ToList() : Array.Empty<string>();
        var s = o["Scope"];
        var classes = Strs(s?["Classes"]);
        var scope = new PackScope((bool?)s?["Full"] ?? false, Strs(s?["Kinds"]), Strs(s?["Methods"]), Strs(s?["Items"]), classes.Count > 0 ? classes : null);
        var items = new List<CandidateItem>();
        foreach (var it in o["Items"] as JsonArray ?? new JsonArray())
        {
            var kind = (string?)it?["Kind"] ?? ""; var key = (string?)it?["ItemKey"] ?? "";
            if (!TemplateConformance.TemplatedKinds.Contains(kind, StringComparer.Ordinal)) throw new InvalidOperationException($"the pack holds '{kind}/{key}', which is not a templated kind");
            var engine = (string?)it?["Engine"]; var method = (string?)it?["Method"];
            var body = (string?)it?["Body"] ?? "";
            var mid = !string.IsNullOrEmpty(engine) && !string.IsNullOrEmpty(method) ? engine + "/" + method : TemplateMethods.Of(kind, key, (string?)it?["Source"], body).Id;
            items.Add(new CandidateItem(kind, key, mid, ((string?)it?["ContentHash"] ?? "").Trim(), body, (string?)it?["Format"] ?? "json", (string?)it?["Version"] ?? v));
        }
        var min = o["MinCodeVersion"] is JsonValue mv ? mv.ToString() : null;
        if (min is not null && !IsPackVersion(min)) throw new InvalidOperationException($"the pack's minimum code version '{min}' is not a version");
        return new TemplatePack(v, (string?)o["CodeVersion"] ?? "", (string?)o["Commit"], scope, (string?)o["Fingerprint"] ?? "", items, sha, o["Name"] is JsonValue nv ? nv.ToString() : null,
            o["Content"] is JsonValue cv ? cv.ToString() : null, min);
    }

    public async Task<IReadOnlyList<InstalledTemplate>> InstalledAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(TemplatesSql, new Dictionary<string, object?>(), ct)).Select(r => new InstalledTemplate(
            r.Str("Kind") ?? "", r.Str("ItemKey") ?? "", r.Str("Version"), r.Str("ContentHash")?.Trim(), r.Str("BodyJson"), r.Str("Format") ?? "json", r.Str("Source"),
            r.Date("RetiredAt"), (int)(r.Long("SortOrder") ?? 0))).Where(t => !TemplateConformance.IsFormerTemplateKind(t.Kind)).ToList();

    public async Task<IReadOnlyDictionary<string, string>> OverridesAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(OverridesSql, new Dictionary<string, object?>(), ct))
            .Where(r => !TemplateConformance.IsFormerTemplateKind(r.Str("Kind")))
            .GroupBy(r => (r.Str("Kind") ?? "") + "/" + (r.Str("ItemKey") ?? ""), StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Str("State") ?? "", StringComparer.Ordinal);

    public async Task<IReadOnlyDictionary<string, InstallStateRow>> InstallStateAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(InstallSql, new Dictionary<string, object?>(), ct))
            .Select(r => new InstallStateRow(r.Str("Name") ?? "", r.Str("Value") ?? "", r.Str("Version"), r.Date("UpdatedAt"), r.Str("UpdatedBy")))
            .ToDictionary(r => r.Name, StringComparer.Ordinal);

    public async Task<IReadOnlyList<ReleaseHistoryRow>> HistoryAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(HistorySql, new Dictionary<string, object?>(), ct))
            .Select(r => new ReleaseHistoryRow(r.Long("ChangeId") ?? 0, r.Str("Kind") ?? "", r.Str("NewValue"), r.Date("ChangedAt"), r.Str("ChangedBy"), r.Str("Reason"))).ToList();

    /// #405: is "Hold Microsoft content" on? (Display only -- the publish job reads the same setting and decides.)
    public async Task<bool> HoldAsync(CancellationToken ct)
    {
        try
        {
            var v = (await _sql.QueryAsync(HoldSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Str("ValueJson")?.Trim().Trim('"').ToLowerInvariant();
            return v is "true" or "1" or "on" or "yes";
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    /// #405: the previous Microsoft content a one-click roll back goes to -- the newest kept version below the installed one.
    public static string? PreviousMicrosoftVersion(IReadOnlyList<string> versions, string? installed) =>
        installed is null ? null : versions.Where(v => CompareVersions(v, installed) < 0).OrderByDescending(v => v, Comparer<string>.Create(CompareVersions)).FirstOrDefault();

    /// Every version a template revision was first published with, newest first: what a roll back can go to.
    public async Task<(IReadOnlyList<string> Versions, IReadOnlyList<SqlRow> Rows)> RevisionsAsync(CancellationToken ct)
    {
        var rows = (await _sql.QueryAsync(RevisionsSql, new Dictionary<string, object?>(), ct)).Where(r => !TemplateConformance.IsFormerTemplateKind(r.Str("Kind"))).ToList();
        var versions = rows.Select(r => r.Str("Version") ?? "").Where(IsPackVersion).Distinct(StringComparer.Ordinal)
            .OrderByDescending(v => v, Comparer<string>.Create(CompareVersions)).ToList();
        return (versions, rows);
    }

    // ------------------------------------------------------------------------------------------------- the diff

    /// Get-SIProTemplatePackDiff: what releasing -candidates would do to the templates in force, within -scope.
    public static ReleaseDiff Diff(IReadOnlyList<CandidateItem> candidates, IReadOnlyList<InstalledTemplate> installed, PackScope scope, IReadOnlyDictionary<string, string>? overrides = null, TemplateClasses? classes = null)
    {
        overrides ??= new Dictionary<string, string>();
        classes ??= TemplateClasses.Shipped;
        // #251: an installed row of a former template kind (names, the CMDB ownership map) is configuration history -- a
        // release never lists, retires or changes it. (A pack cannot carry one: ParsePack refuses it.)
        installed = installed.Where(t => !TemplateConformance.IsFormerTemplateKind(t.Kind)).ToList();
        var have = installed.GroupBy(t => t.Name, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var items = new List<ReleaseDiffItem>();
        var ship = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in candidates)
        {
            ship.Add(c.Name);
            have.TryGetValue(c.Name, out var e);
            var live = e is not null && e.RetiredAt is null;
            var old = live ? e!.ContentHash ?? "" : "";
            var change = !live ? Added : old != c.ContentHash ? Changed : Unchanged;
            items.Add(new ReleaseDiffItem(c.Kind, c.ItemKey, c.MethodId, change, live ? old : null, c.ContentHash, overrides.TryGetValue(c.Name, out var o) ? o : null, c.Format, live ? e!.Body : null, c.Body));
        }
        foreach (var e in have.Values)
        {
            if (ship.Contains(e.Name) || e.RetiredAt is not null) continue;
            var mid = e.MethodId;
            if (!scope.Covers(e.Kind, e.Name, mid, scope.HasClasses ? classes.Of(e.Kind, e.ItemKey) : null)) continue;
            items.Add(new ReleaseDiffItem(e.Kind, e.ItemKey, mid, Retired, e.ContentHash, null, overrides.TryGetValue(e.Name, out var o) ? o : null, e.Format, e.Body, null));
        }
        items.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        var methods = items.GroupBy(i => i.MethodId, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new MethodSummary(g.Key, g.Count(i => i.Change == Added), g.Count(i => i.Change == Changed), g.Count(i => i.Change == Retired),
                g.Count(i => i.Change == Unchanged), g.Count(i => i.Affected))).ToList();
        return new ReleaseDiff(items, methods);
    }

    /// Get-SIProSelectionFingerprint: SHA-256 over '<kind>/<key>=<ContentHash>' (or '=retired') of the selected methods'
    /// items, ordinal, newline-joined. "" when nothing is selected.
    public static string SelectionFingerprint(ReleaseDiff diff, IReadOnlyCollection<string>? methods)
    {
        var all = methods is null || methods.Count == 0 || methods.Contains(AllMethods);
        var lines = diff.Items.Where(i => all || methods!.Contains(i.MethodId)).Select(i => i.Name + "=" + (i.Change == Retired ? "retired" : i.NewHash)).ToArray();
        if (lines.Length == 0) return "";
        Array.Sort(lines, StringComparer.Ordinal);
        return TextSha256(string.Join("\n", lines));
    }

    /// Get-SIProRollbackRows: per installed item (live or retired), the newest revision not newer than -version.
    public static IReadOnlyList<CandidateItem> RollbackCandidates(IReadOnlyList<InstalledTemplate> installed, IReadOnlyList<SqlRow> revisions, string version, string? cls = null, TemplateClasses? classes = null)
    {
        // #405: the one-click roll back of one class (Microsoft content) -- only that class's items
        if (cls is not null) { classes ??= TemplateClasses.Shipped; installed = installed.Where(t => classes.Of(t.Kind, t.ItemKey) == cls).ToList(); }
        var best = new Dictionary<string, SqlRow>(StringComparer.Ordinal);
        foreach (var r in revisions)
        {
            var v = r.Str("Version") ?? "";
            if (CompareVersions(v, version) > 0) continue;
            var name = (r.Str("Kind") ?? "") + "/" + (r.Str("ItemKey") ?? "");
            if (!best.TryGetValue(name, out var cur) || CompareVersions(v, cur.Str("Version")) > 0) best[name] = r;
        }
        var list = new List<CandidateItem>();
        foreach (var t in installed)
            if (best.TryGetValue(t.Name, out var r))
                list.Add(new CandidateItem(t.Kind, t.ItemKey, t.MethodId, (r.Str("ContentHash") ?? "").Trim(), r.Str("BodyJson") ?? "", r.Str("Format") ?? "json", r.Str("Version") ?? ""));
        return list;
    }

    /// The diff of one staged pack against this install, or of a roll back to a version.
    public async Task<(ReleaseDiff Diff, TemplatePack? Pack)> DiffAsync(string mode, string version, CancellationToken ct, string? cls = null)
    {
        if (cls is not null && !TemplateClasses.IsClass(cls)) throw new ArgumentException($"'{cls}' is not a template class");
        var installed = await InstalledAsync(ct);
        var overrides = await OverridesAsync(ct);
        if (mode == "rollback")
        {
            if (!IsPackVersion(version)) throw new ArgumentException($"'{version}' is not a version");
            var (_, rows) = await RevisionsAsync(ct);
            var scope = cls is null ? PackScope.Everything : PackScope.Everything with { Classes = new[] { cls } };
            return (Diff(RollbackCandidates(installed, rows, version, cls), installed, scope, overrides), null);
        }
        var pack = await PackAsync(version, ct);
        return (Diff(pack.Items, installed, pack.Scope, overrides), pack);
    }

    /// The selection as posted -> method ids that exist in the diff (ordinal); "*" or nothing = every method.
    public static (IReadOnlyList<string> Methods, IReadOnlyList<string> Problems) Select(ReleaseDiff diff, IEnumerable<string>? posted, bool all)
    {
        var known = diff.Methods.Select(m => m.Id).ToHashSet(StringComparer.Ordinal);
        if (all) return (new[] { AllMethods }, Array.Empty<string>());
        var sel = (posted ?? Array.Empty<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).Distinct(StringComparer.Ordinal).ToList();
        if (sel.Count == 0) return (Array.Empty<string>(), new[] { "select at least one detection method (or release all)" });
        var bad = sel.Where(s => !IsMethodId(s) || !known.Contains(s)).ToList();
        if (bad.Count > 0) return (Array.Empty<string>(), new[] { "not a detection method of this release: " + string.Join(", ", bad.Take(5)) });
        sel.Sort(StringComparer.Ordinal);
        return (sel, Array.Empty<string>());
    }

    // ------------------------------------------------------------------------------------------------- the release

    /// Start caj-si-templates for an accepted release / roll back -- after re-checking that the fingerprint the Admin
    /// accepted is STILL what the release would put in force -- then record the request in the Admin's name.
    public async Task<WriteResult> StartAsync(string mode, string version, IReadOnlyList<string> methods, string acceptedFingerprint, string by, string? reason, CancellationToken ct, string? cls = null)
    {
        if (mode is not ("release" or "rollback")) return new WriteResult(WriteStatus.Refused, $"unknown template release mode '{mode}'");
        if (cls is not null && (mode != "rollback" || !TemplateClasses.IsClass(cls))) return new WriteResult(WriteStatus.Refused, $"a class ('{cls}') selects the items of a roll back only");
        if (!IsPackVersion(version)) return new WriteResult(WriteStatus.Refused, $"'{version}' is not a version");
        if (!Sha.IsMatch(acceptedFingerprint ?? "")) return new WriteResult(WriteStatus.Refused, "the accepted fingerprint is not known -- stage the release again");
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        if (methods.Count == 0 || methods.Any(m => m != AllMethods && !IsMethodId(m))) return new WriteResult(WriteStatus.Refused, "the selection is not valid -- stage the release again");
        if (!_jobs.IsConfigured) return new WriteResult(WriteStatus.Refused, NotConfiguredJobsClient.Why + " The template release job cannot be started -- nothing was written.");
        var (diff, _) = await DiffAsync(mode, version, ct, cls);
        var now = SelectionFingerprint(diff, methods);
        if (!string.Equals(now, acceptedFingerprint, StringComparison.Ordinal))
            return new WriteResult(WriteStatus.Stale, "the pack, the selection or your templates changed since this was staged -- nothing was started; discard it and stage it again");
        var env = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["SI_TEMPLATES_MODE"] = mode, ["SI_TEMPLATES_PACK"] = version, ["SI_TEMPLATES_METHODS"] = string.Join(";", methods),
            ["SI_TEMPLATES_ACCEPT_FINGERPRINT"] = acceptedFingerprint!, ["SI_TEMPLATES_REQUESTED_BY"] = by.Length > 200 ? by[..200] : by,
        };
        if (cls is not null) env["SI_TEMPLATES_CLASS"] = cls;
        string execution;
        try { execution = await _jobs.StartWithEnvAsync(JobName, env, ct); }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or HttpRequestException)
        {
            return new WriteResult(WriteStatus.Refused, $"the template release job {JobName} could not be started: {ex.Message} -- nothing was written");
        }
        var valueObj = new JsonObject
        {
            ["Mode"] = mode, ["Pack"] = version, ["Methods"] = new JsonArray(methods.Select(m => (JsonNode?)JsonValue.Create(m)).ToArray()),
            ["Selection"] = acceptedFingerprint, ["Job"] = JobName, ["Execution"] = execution,
        };
        if (cls is not null) valueObj["Classes"] = new JsonArray(JsonValue.Create(cls));
        var value = valueObj.ToJsonString();
        var why = string.IsNullOrWhiteSpace(reason) ? $"{mode} of template pack {version} accepted" : reason.Trim();
        await _sql.QueryAsync(RequestSql, new Dictionary<string, object?> { ["Value"] = value, ["By"] = by.Length > 256 ? by[..256] : by, ["Reason"] = why.Length > 400 ? why[..400] : why }, ct);
        return new WriteResult(WriteStatus.Saved, $"the template {mode} job started ({execution}); the release is recorded when the job has written and verified it -- see Template releases");
    }

    /// Is the release job one of this installation's jobs? null when the jobs view is not configured (nothing to say).
    /// Setup and every update deploy it (#250); until then the page says so in plain words.
    public async Task<bool?> JobInstalledAsync(CancellationToken ct)
    {
        if (!_jobs.IsConfigured) return null;
        return (await _jobs.ListAsync(ct)).Any(j => string.Equals(j.Name, JobName, StringComparison.Ordinal));
    }

    public async Task<IReadOnlyList<JobExecution>> ExecutionsAsync(CancellationToken ct)
    {
        if (!_jobs.IsConfigured) return Array.Empty<JobExecution>();
        return await _jobs.ExecutionsAsync(JobName, 10, ct);
    }

    /// One line per method for the Review &amp; commit page.
    public static string Describe(ReleaseDiff diff, IReadOnlyCollection<string> methods)
    {
        var all = methods.Contains(AllMethods);
        var lines = diff.Methods.Where(m => all || methods.Contains(m.Id)).Where(m => m.HasChanges)
            .Select(m => $"{m.Id}: {m.Added} new, {m.Changed} changed, {m.Retired} retired" + (m.Affected > 0 ? $" -- {m.Affected} of your overridden items affected" : "")).ToList();
        return lines.Count == 0 ? "(no rule changes what it does -- versions only)" : string.Join("\n", lines);
    }
}
