using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// EVERY COLUMN ON EVERY DATA VIEW (owner 2026-10-11: "al views must support to add all available columns. i decided what
// to view, not you"). A data view whose rows ARE CIs or are tied to one (a finding on an asset, a record of a CI, a CMDB
// item...) offers, next to its own columns: the CI id, every field of the CI document, one column per identifier type
// with its VALUE(S), the linked objects (every id), and every property each source reported (the Full details level:
// source.property, ONE nested level, deeper = compact JSON). A view of findings also offers every field of the finding.
//
// These columns are computed LATE: for the rows of the page shown (or the rows exported) only, by their CI key -- never
// over every CI to choose rows (the page is chosen first, then its <= 200 rows are looked up by key: seeks on
// sidata.Ci / AssetIdentifier / CiLink / CiRecord / RecordIdentifier / AssetMetadata). The column keys live in one
// namespace (<see cref="DataColumnKeys"/>) next to the view's own column keys, so one stored layout (cfg.ColumnLayout)
// holds both.
// =====================================================================================================================

/// How a data view's rows reach their CI: not at all, by the CI id (sidata.Ci.CiId), or by the collection's asset key
/// (sidata.Asset.AssetKey: mostly the CI id; else a source's native id, matched via sidata.CiLink / 'az:' + an ARM id).
public enum RowCiKey { None, CiId, AssetKey }

/// How a data view's rows reach their finding(s): not at all, one finding of the collection (sidata.Finding.FindingId), or
/// every finding of a CVE in the collection (a per-CVE aggregate row: its software, description, fix and affected assets).
public enum RowFindingKey { None, FindingId, Cve, Issue }

/// <summary>
/// A finding CONTEXT column (owner 2026-10-11: "i cannot see what app it is related. no remediation, nothing"): one
/// meaning -- the affected software, the description, the fix -- read from the finding's row under the first of
/// <see cref="Fields"/> it carries (the Risk Analysis outputs name the same thing differently per report, and the si_
/// names arrive with a later release: both are read, si_ first). <see cref="Flags"/>: a yes/no column made of flags (the
/// exploit signals). <see cref="AggregateOnly"/>: offered on a per-CVE row only (the affected assets).
/// </summary>
public sealed record FindingContext(string Key, string Label, IReadOnlyList<string> Fields, IReadOnlyList<(string Field, string Words)>? Flags = null, bool AggregateOnly = false);

/// <summary>The keys of the extra columns, their groups and their labels. PURE.</summary>
public static partial class DataColumnKeys
{
    /// The CI id.
    public const string CiId = "ci.id";
    /// Every linked object id (the records the correlation joined into the CI).
    public const string Links = "ci.links";
    /// ci.f.&lt;CI document field&gt;
    public const string FieldPrefix = "ci.f.";
    /// ci.i.&lt;identifier type&gt; -- its value(s)
    public const string IdPrefix = "ci.i.";
    /// ci.s.&lt;source&gt;.&lt;property&gt;[.&lt;child&gt;] -- the <see cref="CiExportFlatten.Metadata"/> column name after the prefix
    public const string SourcePrefix = "ci.s.";
    /// fi.&lt;finding field&gt; (the finding's whole row, sidata.Finding.DetailJson)
    public const string FindingPrefix = "fi.";
    /// fc.&lt;context&gt; -- a finding context column (<see cref="Context"/>)
    public const string ContextPrefix = "fc.";

    public const string Software = "fc.software";
    public const string Vendor = "fc.vendor";
    public const string Version = "fc.version";
    public const string Description = "fc.description";
    public const string Fix = "fc.fix";
    public const string FixId = "fc.fixid";
    public const string Remediation = "fc.remediation";
    public const string MoreDetails = "fc.moredetails";
    public const string Published = "fc.published";
    public const string Exploit = "fc.exploit";
    public const string Category = "fc.category";
    public const string Subcategory = "fc.subcategory";
    /// #772 the finding's component and its ServiceNow sub-CI (the classification's one value each); owner 2026-10-19: the
    /// component (OS, SQL, Network ...) is prepared and shown by default
    public const string Component = "fc.component";
    public const string SubCi = "fc.subci";
    /// #772 the OS family of the finding's asset (Windows, Linux, ...)
    public const string OsFamily = "fc.osfamily";
    /// #772 the finding's patch cycle (In monthly cycle / Catch-up / No fix available / Unknown)
    public const string PatchCycle = "fc.patchcycle";
    public const string Impact = "fc.impact";
    public const string Cmdb = "fc.cmdb";
    public const string CmdbId = "fc.cmdbid";
    public const string CmdbCriticality = "fc.cmdbcriticality";
    public const string Assets = "fc.assets";
    // the context the sources add (owner 2026-10-11: "rich context, single overview, ability to prioritize")
    public const string Epss = "fc.epss";
    public const string CveTags = "fc.cvetags";
    public const string Mitigation = "fc.mitigation";
    public const string EosStatus = "fc.eosstatus";
    public const string EosDate = "fc.eosdate";
    public const string FixOwner = "fc.fixowner";
    public const string FixDue = "fc.fixdue";
    public const string FixGrace = "fc.fixgrace";
    public const string Evidence = "fc.evidence";
    public const string SourceFirst = "fc.sourcefirst";
    public const string ScoreGain = "fc.scoregain";
    public const string ScoreControl = "fc.scorecontrol";
    public const string AttackPathCount = "fc.attackpathcount";
    public const string AttackPaths = "fc.attackpaths";
    public const string CertExpiry = "fc.certexpiry";
    public const string CvssVector = "fc.cvssvector";
    public const string ExploitTypes = "fc.exploittypes";
    public const string ExposedDevices = "fc.exposeddevices";
    public const string AffectedPath = "fc.affectedpath";
    public const string StatusCause = "fc.statuscause";
    public const string UserImpact = "fc.userimpact";
    public const string Effort = "fc.effort";
    public const string PortalLink = "fc.portallink";

    /// The finding context columns, in the order a view shows them. The si_ names (si_fix_recommended_update,
    /// si_fix_recommended_update_id, si_fix_remediation, ...) are read first: they arrive with the data fix that adds the
    /// recommended security update and the remediation options, and stay empty until then.
    /// <para>A HEADING IS ONE COLUMN'S OWN: no view shows or offers two columns under the same heading (a guard test holds
    /// every data view to it). So a context column whose plain word a view's own column already carries says what it is --
    /// what the FINDING carries (its category, subcategory, impact, CMDB item), the exploit signals in words next to a
    /// view's yes / no "Exploit", the NAMES of the affected assets next to a view's count. Only the heading: the key, the
    /// stored column and what a saved layout holds are unchanged.</para>
    public static readonly IReadOnlyList<FindingContext> Context =
    [
        new(Software, "Affected software", [AffectedSoftwareField, "si_affected_product", "SI_AffectedProduct", "si_software_name", "SoftwareName"]),
        new(Vendor, "Vendor", ["si_affected_vendor", "SI_AffectedVendor", "si_software_vendor", "SoftwareVendor"]),
        new(Version, "Version(s)", ["si_affected_version", "SI_AffectedVersion", "si_software_version", "SoftwareVersion"]),
        new(Description, "Description", ["si_description", "CVSSDesc", "VulnerabilityDescription", "FindingDescription", "si_configuration_description", "ConfigurationDescription", "KB_Description", "Description"]),
        new(Fix, "Fix (recommended update)", ["si_fix_recommended_update", "RecommendedSecurityUpdate", "SI_FixReference", "si_fix_reference"]),
        new(FixId, "Fix id (KB)", ["si_fix_recommended_update_id", "RecommendedSecurityUpdateId"]),
        new(Remediation, "Remediation", ["si_fix_remediation", "RemediationOptions", "KB_Remediation", "si_recommended_action", "RecommendedAction", "Remediation"]),
        new(MoreDetails, "More details", ["si_more_details", "MoreDetails", "CveUrl", "FindingReferenceUrl"]),
        new(Published, "Published / modified", ["si_published_date", "PublishedDate", "si_cve_last_modified", "CVELastModified"]),
        new(Exploit, "Exploit details", [], [("HasExploit", "exploit available"), ("IsExploitVerified", "exploit verified"), ("IsInExploitKit", "in an exploit kit"), ("IsZeroDay", "zero-day")]),
        new(Category, "Finding category", ["si_category", "Category"]),
        new(Subcategory, "Finding subcategory", ["si_subcategory", "Subcategory"]),
        // #772 the component and, right after it, the ServiceNow sub-CI the finding is linked under (OS / SQL / Other by default)
        new(Component, "Component (finding)", ["si_component", "Component"]),
        new(SubCi, "ServiceNow sub-CI (finding)", ["si_servicenow_subci"]),
        new(OsFamily, "OS family (finding)", ["si_os_family"]),
        new(PatchCycle, "Patch cycle (finding)", ["si_patch_cycle"]),
        new(Impact, "Finding impact", ["si_impact", "Impact", "ConfigurationImpact"]),
        new(CmdbId, "Finding CMDB id (sys_id)", ["si_cmdb_id", "cmdbId"]),
        new(Cmdb, "Finding CMDB name", ["si_cmdb_name", "cmdbName"]),
        new(CmdbCriticality, "Finding CMDB criticality", ["si_cmdb_criticality", "cmdbCriticality"]),
        // what the sources add about a finding: how likely it is exploited, whether it is mitigated, whether the software
        // is still supported, who fixes it by when, the evidence, the attack paths it is on
        new(Epss, "EPSS (exploit probability)", ["si_epss"]),
        new(CveTags, "CVE tags", ["si_cve_tags"]),
        new(Mitigation, "Mitigation status", ["si_cve_mitigation_status"]),
        new(EosStatus, "End-of-support status", ["si_eos_status"]),
        new(EosDate, "End-of-support date", ["si_eos_date"]),
        new(FixOwner, "Fix owner", ["si_fix_owner"]),
        new(FixDue, "Fix due date", ["si_fix_due_date"]),
        new(FixGrace, "Fix grace period", ["si_fix_grace_period"]),
        new(Evidence, "Evidence", ["si_evidence"]),
        new(SourceFirst, "First detected by the source", ["si_source_first_seen", "si_source_first_detected"]),
        new(ScoreGain, "Secure score gain", ["si_secure_score_gain"]),
        new(ScoreControl, "Secure score control", ["si_secure_score_control"]),
        new(AttackPathCount, "Attack paths", ["si_attack_path_count"]),
        new(AttackPaths, "Attack path names", ["si_attack_paths"]),
        new(CertExpiry, "Certificate expiry", ["si_certificate_expiry"]),
        new(CvssVector, "CVSS vector", ["si_cvss_vector"]),
        new(ExploitTypes, "Exploit types", ["si_exploit_types"]),
        new(ExposedDevices, "Exposed devices", ["si_exposed_devices"]),
        new(AffectedPath, "Affected path", ["si_affected_path"]),
        new(StatusCause, "Status cause", ["si_status_cause"]),
        new(UserImpact, "User impact", ["si_user_impact", "UserImpact"]),
        new(Effort, "Remediation effort", ["si_remediation_effort", "ImplementationEffort"]),
        new(PortalLink, "Portal link", ["si_portal_link", "PortalUrl"]),
        new(Assets, "Affected asset names", [], AggregateOnly: true),
    ];

    public static FindingContext? ContextOf(string key) => Context.FirstOrDefault(c => c.Key == key);

    /// The finding's software as one text, "Name Version (Vendor)" items ';'-joined (the fix-data release, #590).
    public const string AffectedSoftwareField = "si_affected_software";

    /// <summary>
    /// CI fields every view offers whether or not this database's documents carry them yet (owner 2026-10-11: "we need both
    /// ids like sub id + sub names"): the NAME (or id) half of a reference whose other half the data has today. They read
    /// empty until the data carries them; the view still shows the pair.
    /// </summary>
    public static readonly IReadOnlyList<string> PairFields =
    [
        "si_azure_subscription_id", "si_azure_subscription_name", "si_management_group_id", "si_management_group_path",
        "si_azure_resource_group", "si_app_id", "si_app_name", "si_display_name", "si_owner", "si_owner_ids", "si_owner_upns",
        "si_cmdb_id", "si_cmdb_name",
        // the pairs the sources add: both halves are offered wherever a row is tied to a CI
        "si_azure_tenant_id", "si_azure_tenant_name", "si_management_group_name", "si_service_support_group_id", "si_service_support_group",
        "si_service_assignment_group_id", "si_service_assignment_group", "si_service_owner_id", "si_service_owner", "si_cmdb_support_group_id",
        "si_cmdb_support_group", "si_cmdb_assignment_group_id", "si_cmdb_assignment_group", "si_cmdb_owner_id", "si_cmdb_owner",
        "si_primary_user_id", "si_primary_user_upn", "si_primary_user_name", "si_manager_id", "si_manager_upn", "si_manager_name",
        "si_attached_resource_id", "si_attached_resource_name", "si_attached_resource", "si_backup_vault_id", "si_backup_vault_name",
    ];

    /// <summary>
    /// One name for one thing: eight early field names that were never in the field catalog (the tenant is
    /// si_azure_tenant_id / si_azure_tenant_name, the owners si_owner_ids / si_owner_upns; the others have no field). No
    /// view offers them, nothing fills them, and a stored layout that still names one simply loses that column.
    /// </summary>
    public static readonly IReadOnlySet<string> RetiredFields = new HashSet<string>(StringComparer.Ordinal)
    {
        "si_tenant_id", "si_tenant_name", "si_owner_object_id", "si_owner_upn", "si_azure_resource_group_id", "si_sp_object_id", "si_group_id", "si_group_name",
    };

    /// Whether a key is a CI field column of a retired name (<see cref="RetiredFields"/>).
    public static bool IsRetired(string key) => FieldOf(key) is { } field && RetiredFields.Contains(field);

    public const string GroupContext = "Finding context";
    public const string GroupView = "This view";
    public const string GroupCi = "CI";
    public const string GroupLinks = "Linked objects";
    public const string GroupIdentifiers = "Identifiers";
    public const string GroupFinding = "Finding fields";
    public const string SourceGroupPrefix = "Source: ";
    public static string GroupSource(string source) => SourceGroupPrefix + source;

    /// The identifier types always offered (a database that has not seen one yet still offers it).
    public static readonly IReadOnlyList<string> KnownIdentifierTypes = ["AadDeviceId", "AzureResourceId", "ExposureGraphNodeId", "MdeDeviceId", "SI_AssetId"];

    /// The identifier type the linked objects are recorded under (sidata.AssetIdentifier).
    public const string MemberType = "SI_AssetId";

    /// How several values of one cell are joined.
    public const string Separator = "; ";

    /// The longest key (a source property path can be long).
    public const int MaxKey = 400;

    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9_\-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9_\-]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex SourcePattern();

    public static bool IsExtra(string? key) => key is not null && (key.StartsWith("ci.", StringComparison.Ordinal) || key.StartsWith(FindingPrefix, StringComparison.Ordinal)
        || key.StartsWith(ContextPrefix, StringComparison.Ordinal));

    /// Whether a key is a well-formed extra column key (what a stored layout and a save may hold).
    public static bool IsValid(string? key)
    {
        if (string.IsNullOrEmpty(key) || key.Length > MaxKey || key.Any(char.IsControl)) return false;
        if (key is CiId or Links) return true;
        if (key.StartsWith(FieldPrefix, StringComparison.Ordinal)) return NamePattern().IsMatch(key[FieldPrefix.Length..]);
        if (key.StartsWith(IdPrefix, StringComparison.Ordinal)) return NamePattern().IsMatch(key[IdPrefix.Length..]);
        if (key.StartsWith(FindingPrefix, StringComparison.Ordinal)) return NamePattern().IsMatch(key[FindingPrefix.Length..]);
        if (key.StartsWith(SourcePrefix, StringComparison.Ordinal)) return SourceOf(key) is not null;
        if (key.StartsWith(ContextPrefix, StringComparison.Ordinal)) return ContextOf(key) is not null;
        return false;
    }

    public static string? FieldOf(string key) => key.StartsWith(FieldPrefix, StringComparison.Ordinal) ? key[FieldPrefix.Length..] : null;
    public static string? IdTypeOf(string key) => key.StartsWith(IdPrefix, StringComparison.Ordinal) ? key[IdPrefix.Length..] : null;
    public static string? FindingFieldOf(string key) => key.StartsWith(FindingPrefix, StringComparison.Ordinal) ? key[FindingPrefix.Length..] : null;

    /// "ci.s.mde.osPlatform" -> (Source "mde", Name "mde.osPlatform" -- the flattened column name); null when not one.
    public static (string Source, string Name)? SourceOf(string key)
    {
        if (!key.StartsWith(SourcePrefix, StringComparison.Ordinal)) return null;
        var name = key[SourcePrefix.Length..];
        var dot = name.IndexOf('.');
        if (dot <= 0 || dot == name.Length - 1) return null;
        var source = name[..dot];
        return SourcePattern().IsMatch(source) ? (source, name) : null;
    }

    public static string Field(string field) => FieldPrefix + field;
    public static string Id(string type) => IdPrefix + type;
    public static string Source(string flattenedName) => SourcePrefix + flattenedName;
    public static string Finding(string field) => FindingPrefix + field;

    /// Whether the key needs the rows' CI (every ci.* key) or the finding (fi.*).
    public static bool IsCi(string key) => key.StartsWith("ci.", StringComparison.Ordinal);
    public static bool IsFinding(string key) => key.StartsWith(FindingPrefix, StringComparison.Ordinal) || key.StartsWith(ContextPrefix, StringComparison.Ordinal);

    /// The words of an extra column.
    public static string Label(string key)
    {
        if (key == CiId) return "CI id";
        if (key == Links) return "Linked objects (ids)";
        if (FieldOf(key) is { } f) return (CiFieldWords.TryGetValue(f, out var w) ? w : CiColumns.LabelOf(f)) + " (CI)";
        if (IdTypeOf(key) is { } t) return t == MemberType ? "SI asset id (linked objects)" : t;
        if (SourceOf(key) is { } s) return s.Name;
        // a finding's SI field reads "(finding)"; a column the Risk Analysis report carries as it is reads "(report)" -- so
        // si_category and the report's own Category never share a heading
        if (FindingFieldOf(key) is { } ff)
        {
            var words = FieldWords(ff) + (ff.StartsWith("si_", StringComparison.Ordinal) ? " (finding)" : " (report)");
            // a field the prepared context column of the same words reads (si_component -> "Component (finding)") says it
            // is the finding row's own value, so the two never share a heading
            return Context.Any(c => c.Label == words) ? FieldWords(ff) + " (finding row)" : words;
        }
        if (ContextOf(key) is { } fc) return fc.Label;
        return key;
    }

    /// <summary>
    /// CI fields whose derived name misleads (owner 2026-10-19): the asset's component LIST read "Components (CI)" next to
    /// the finding's single "Component" -- it is what is installed on the asset, so it says so.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> CiFieldWords = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["si_components"] = "Installed on asset",
    };

    /// <summary>
    /// A finding field as words (owner 2026-10-19: the column picker showed si_component, RiskFactor_Probability_Detailed):
    /// "si_component" -> "Component", "RiskFactor_Probability_Detailed" -> "Risk factor probability detailed". The technical
    /// name stays the column's key, shown small under the label in the picker.
    /// </summary>
    public static string FieldWords(string field)
    {
        if (field.StartsWith("si_", StringComparison.Ordinal)) return CiColumns.LabelOf(field);
        var words = new List<string>();
        foreach (var part in field.Split('_', StringSplitOptions.RemoveEmptyEntries))
            words.AddRange(CamelWords().Split(part).Where(w => w.Length > 0));
        if (words.Count == 0) return field;
        var text = string.Join(" ", words.Select((w, i) => i == 0 || w.All(char.IsUpper) ? w : w.ToLowerInvariant()));
        return char.ToUpperInvariant(text[0]) + text[1..];
    }

    /// The technical name of a column key as the data has it (the field, the property path, the identifier type).
    public static string TechnicalName(string key) =>
        FieldOf(key) ?? FindingFieldOf(key) ?? (SourceOf(key) is { } s ? s.Name : null) ?? IdTypeOf(key) ?? key;

    // "RiskFactor" -> "Risk", "Factor"; "CVSSScore" -> "CVSS", "Score"
    [GeneratedRegex(@"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", RegexOptions.CultureInvariant)]
    private static partial Regex CamelWords();

    /// The group an extra column is offered under in the chooser.
    public static string Group(string key)
    {
        if (key is CiId) return GroupCi;
        if (key is Links) return GroupLinks;
        if (key.StartsWith(FieldPrefix, StringComparison.Ordinal)) return GroupCi;
        if (key.StartsWith(IdPrefix, StringComparison.Ordinal)) return GroupIdentifiers;
        if (SourceOf(key) is { } s) return GroupSource(s.Source);
        if (key.StartsWith(FindingPrefix, StringComparison.Ordinal)) return GroupFinding;
        if (key.StartsWith(ContextPrefix, StringComparison.Ordinal)) return GroupContext;
        return GroupView;
    }

    /// Several values of one cell as one: one value keeps its type (a number stays a number), several are joined as text.
    public static object? Join(IEnumerable<object?> values)
    {
        var list = values.Where(v => v is not null && !(v is string s && s.Length == 0)).ToList();
        var distinct = list.Select(v => (Text: Text(v), Value: v)).GroupBy(x => x.Text, StringComparer.Ordinal).Select(g => g.First()).ToList();
        return distinct.Count switch
        {
            0 => null,
            1 => distinct[0].Value,
            _ => string.Join(Separator, distinct.Select(x => x.Text)),
        };
    }

    /// A cell value as invariant text.
    public static string Text(object? v) => v switch
    {
        null => "",
        string s => s,
        bool b => b ? "true" : "false",
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => v.ToString() ?? "",
    };
}

/// What the extra columns of the data views are made of: the CI document fields, the identifier types, the source
/// properties (flattened names, "mde.osPlatform") and the finding fields known to this database. Read from samples and
/// the field catalog -- the chooser's list, never a limit on what a layout may hold (a property not in the sample is
/// still kept and filled when a layout names it).
public sealed record DataColumnCatalog(IReadOnlyList<string> CiFields, IReadOnlyList<string> IdentifierTypes, IReadOnlyList<string> SourceProperties, IReadOnlyList<string> FindingFields)
{
    public static readonly DataColumnCatalog Empty = new([], DataColumnKeys.KnownIdentifierTypes, [], []);

    /// Some of the lists are not written yet (a new install before its first data sync, a database before the update): the
    /// chooser offers the columns without them and says they appear after the next data sync.
    public bool Pending { get; init; }

    /// Every extra column a view with these rows offers, in chooser order (key; group and label from <see cref="DataColumnKeys"/>).
    /// <paramref name="ownFields"/>: the CI fields the view's own columns already are (All CIs) -- not offered twice.
    public IReadOnlyList<string> Offered(RowCiKey ci, RowFindingKey findings, IReadOnlySet<string>? ownFields = null)
    {
        var keys = new List<string>();
        if (findings != RowFindingKey.None)
            keys.AddRange(DataColumnKeys.Context.Where(c => findings is RowFindingKey.Cve or RowFindingKey.Issue || !c.AggregateOnly).Select(c => c.Key));
        if (ci != RowCiKey.None)
        {
            keys.Add(DataColumnKeys.CiId);
            keys.AddRange(CiFields.Union(DataColumnKeys.PairFields, StringComparer.Ordinal).Where(f => !DataColumnKeys.RetiredFields.Contains(f) && (ownFields is null || !ownFields.Contains(f)))
                .OrderBy(f => f, StringComparer.Ordinal).Select(DataColumnKeys.Field));
            keys.AddRange(DataColumnKeys.KnownIdentifierTypes.Union(IdentifierTypes, StringComparer.OrdinalIgnoreCase).OrderBy(t => t, StringComparer.OrdinalIgnoreCase).Select(DataColumnKeys.Id));
            keys.Add(DataColumnKeys.Links);
            keys.AddRange(SourceProperties.Select(DataColumnKeys.Source));
        }
        if (findings == RowFindingKey.FindingId) keys.AddRange(FindingFields.Select(DataColumnKeys.Finding));
        return keys.Where(DataColumnKeys.IsValid).Distinct(StringComparer.Ordinal).ToList();
    }
}

/// The values of the extra columns for some rows: owner (the row's key as the row has it) -> column key -> value.
public sealed class DataColumnCells
{
    public static readonly DataColumnCells None = new();
    public Dictionary<string, Dictionary<string, object?>> ByCi { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<long, Dictionary<string, object?>> ByFinding { get; } = new();
    public Dictionary<string, Dictionary<string, object?>> ByCve { get; } = new(StringComparer.OrdinalIgnoreCase);

    public object? Get(string column, string? ciKey, long? findingId, string? cve = null)
    {
        if (DataColumnKeys.IsFinding(column))
        {
            if (findingId is { } f) return ByFinding.TryGetValue(f, out var fr) && fr.TryGetValue(column, out var fv) ? fv : null;
            return cve is { Length: > 0 } c && ByCve.TryGetValue(c, out var cr) && cr.TryGetValue(column, out var cv) ? cv : null;
        }
        return ciKey is { Length: > 0 } k && ByCi.TryGetValue(k, out var r) && r.TryGetValue(column, out var v) ? v : null;
    }
}

/// The reads behind the extra columns. Read-only; keys travel as ONE JSON array parameter.
public interface IDataColumnViews
{
    /// What the chooser offers: the lists the data sync wrote (sidata.ColumnChoice), read in one small read and kept while
    /// they stand still. A list not written yet is left out (<see cref="DataColumnCatalog.Pending"/>); the data is never
    /// sampled on a page open. A database without the v3 tables offers the known identifier types only.
    Task<DataColumnCatalog> CatalogAsync(CancellationToken ct);
    /// The wanted ci.* columns for these row keys (<see cref="RowCiKey.CiId"/> or <see cref="RowCiKey.AssetKey"/>).
    Task<IReadOnlyDictionary<string, Dictionary<string, object?>>> CiCellsAsync(RowCiKey kind, IReadOnlyList<string> keys, IReadOnlyCollection<string> wanted, CancellationToken ct);
    /// The wanted fi.* / fc.* columns for these findings of one collection.
    Task<IReadOnlyDictionary<long, Dictionary<string, object?>>> FindingCellsAsync(string collectionId, IReadOnlyList<long> findingIds, IReadOnlyCollection<string> wanted, CancellationToken ct);
    /// The wanted fc.* columns of per-CVE rows: over a sample of each CVE's findings in the collection (the software as a
    /// distinct list, the description, the fix) and its affected assets.
    Task<IReadOnlyDictionary<string, Dictionary<string, object?>>> CveCellsAsync(string collectionId, IReadOnlyList<string> cves, IReadOnlyCollection<string> wanted, CancellationToken ct, bool issues = false);
    /// Which tables and prepared columns the database has (cached; nothing = an empty database).
    Task<DataColumnSchema> SchemaAsync(CancellationToken ct) => Task.FromResult(new DataColumnSchema(false, false, false, false, false, false, false));
}

/// Which tables the database has (a missing one is never named in a statement).
public sealed record DataColumnSchema(bool Ci, bool Links, bool Records, bool Metadata, bool AssetIdentifiers, bool RecordIdentifiers, bool FindingJson)
{
    public CiExportSchema Export => new(Ci, Links, Records, Metadata);
    /// sidata.Ci carries every prepared CI column of <see cref="ViewStoredColumns"/> and its markers (the schema update ran).
    public bool CiStored { get; init; }
    /// sidata.Finding carries the finding context columns, and sidata.IssueContext / Collection.ContextAt exist.
    public bool FindingContext { get; init; }
    /// sidata.ColumnChoice / ColumnChoiceState exist: the chooser's lists are read from there (the data sync writes them).
    public bool Choices { get; init; }
}

/// <summary>The statements. Fixed text assembled from fixed parts by which tables exist; parameters only; read-only.</summary>
public static class DataColumnSql
{
    /// The most keys one read takes (the page is <= 200 rows; an export reads in batches of this).
    public const int Batch = 500;
    /// How many recent objects per source the chooser's property list is read from.
    public const int SourceSample = 100;
    /// How many CI documents / findings the chooser's field lists are read from (plus the field catalog for the CI).
    public const int DocSample = 300;

    public static readonly string Schema = $"""
SELECT CASE WHEN OBJECT_ID(N'sidata.Ci') IS NULL THEN 0 ELSE 1 END AS HasCi,
       CASE WHEN OBJECT_ID(N'sidata.CiLink') IS NULL THEN 0 ELSE 1 END AS HasLink,
       CASE WHEN OBJECT_ID(N'sidata.CiRecord') IS NULL THEN 0 ELSE 1 END AS HasRecord,
       CASE WHEN OBJECT_ID(N'sidata.AssetMetadata') IS NULL THEN 0 ELSE 1 END AS HasMetadata,
       CASE WHEN OBJECT_ID(N'sidata.AssetIdentifier') IS NULL THEN 0 ELSE 1 END AS HasAssetIdentifier,
       CASE WHEN OBJECT_ID(N'sidata.RecordIdentifier') IS NULL THEN 0 ELSE 1 END AS HasRecordIdentifier,
       CASE WHEN COL_LENGTH(N'sidata.Finding', N'DetailJson') IS NULL THEN 0 ELSE 1 END AS HasFindingJson,
       {ViewStoredColumns.CiSchemaProbe} AS HasCiStored,
       {ViewStoredColumns.FindingSchemaProbe} AS HasFindingContext,
       CASE WHEN OBJECT_ID(N'sidata.ColumnChoice') IS NULL OR OBJECT_ID(N'sidata.ColumnChoiceState') IS NULL THEN 0 ELSE 1 END AS HasChoices;
""";

    // ---- the prepared columns (ViewStoredColumns): what a default layout shows, read by key from columns ---------------

    /// The keys and the id of their CI (d: Owner, CiId) -- the CI the key is, else (an asset key) the CI that links it: seeks
    /// on PK_Ci and IX_CiLink_Native. The same rule as <see cref="CiCte"/>, without the document.
    public static string CiKeyCte(DataColumnSchema s, RowCiKey kind)
    {
        if (kind != RowCiKey.AssetKey)
            return Ids + ",\nd AS (SELECT i.Owner, c0.CiId FROM ids AS i JOIN sidata.Ci AS c0 ON c0.CiId = i.Owner)";
        var viaLink = !s.Links ? "" :
            "\n        UNION ALL SELECT l.CiId, 1 FROM sidata.CiLink AS l WHERE l.NativeId = i.Owner" +
            "\n        UNION ALL SELECT l.CiId, 2 FROM sidata.CiLink AS l WHERE i.Owner LIKE N'az:%' AND l.NativeId = SUBSTRING(i.Owner, 4, 450)";
        return Ids + ",\nd AS (\n    SELECT i.Owner, r.CiId\n    FROM ids AS i\n    CROSS APPLY (SELECT TOP (1) x.CiId FROM (\n        SELECT c0.CiId, 0 AS P FROM sidata.Ci AS c0 WHERE c0.CiId = i.Owner"
            + viaLink + "\n    ) AS x ORDER BY x.P) AS r\n)";
    }

    /// <summary>
    /// Each key's CI with the prepared <paramref name="columns"/> of sidata.Ci and whether they are current (RowCur = 1: the
    /// data sync filled them from the CI's current document, for the shipped list @Set). A seek on PK_Ci per key; the
    /// document is not read. The key, the CI id and the mark are RowKey / RowCiId / RowCur: sidata.Ci has a column Owner.
    /// </summary>
    public static string CiStored(DataColumnSchema s, RowCiKey kind, IReadOnlyCollection<string> columns) => "WITH " + CiKeyCte(s, kind) + $"""

SELECT d.Owner AS RowKey, d.CiId AS RowCiId,
       CASE WHEN {ViewStoredColumns.CiCurrentSql} THEN 1 ELSE 0 END AS RowCur{string.Concat(columns.Select(c => $",\n       c.[{c}] AS [{c}]"))}
FROM d
JOIN sidata.Ci AS c ON c.CiId = d.CiId;
""";

    /// The collection's own identifiers of each asset key (a seek on UX_AssetIdentifier_Key per key, covering).
    public const string OwnIdentifiers = "WITH " + Ids + """

SELECT i.Owner, ai.IdentifierType AS T, ai.IdentifierValue AS V
FROM ids AS i
JOIN sidata.AssetIdentifier AS ai ON ai.AssetKey = i.Owner;
""";

    /// <summary>
    /// The findings of one collection by id with their prepared context <paramref name="columns"/> (the clustered key: a
    /// seek per id; DetailJson is not read) and whether the collection's context is prepared FOR THE SHIPPED LIST
    /// (Prepared = 1; @FSet = <see cref="ViewStoredColumns.FindingContextSetId"/>).
    /// </summary>
    public static string FindingsStored(IReadOnlyCollection<string> columns) => $"""
SELECT f.FindingId, CASE WHEN {ViewStoredColumns.CollectionPreparedSql} THEN 1 ELSE 0 END AS Prepared{string.Concat(columns.Select(c => $",\n       f.[{c}] AS [{c}]"))}
FROM sidata.Finding AS f
JOIN sidata.Collection AS k ON k.CollectionId = f.CollectionId
WHERE f.CollectionId = TRY_CONVERT(int, @CollectionId)
  AND f.FindingId IN (SELECT TRY_CONVERT(bigint, j.[value]) FROM OPENJSON(@Ids) AS j);
""";

    /// <summary>
    /// The prepared context of per-CVE / per-issue rows: one row of sidata.IssueContext per key (a seek on its primary key),
    /// and whether the collection's context is prepared. An empty @CollectionId reads the published run's collection.
    /// </summary>
    public static string IssuesStored(IReadOnlyCollection<string> columns) => $"""
WITH col AS (SELECT COALESCE(TRY_CONVERT(int, NULLIF(@CollectionId, N'')), {PublishedRun.DetailedId}) AS Id),
c AS (SELECT DISTINCT CONVERT(nvarchar(256), j.[value]) AS Cve FROM OPENJSON(@Cves) AS j WHERE j.[value] IS NOT NULL AND j.[value] <> N'')
SELECT c.Cve, CASE WHEN {ViewStoredColumns.CollectionPreparedSql} THEN 1 ELSE 0 END AS Prepared, x.Assets, x.AssetNamesShown, x.AssetNames{string.Concat(columns.Select(n => $",\n       x.[{n}] AS [{n}]"))}
FROM c
CROSS JOIN col
LEFT JOIN sidata.Collection AS k ON k.CollectionId = col.Id
LEFT JOIN sidata.IssueContext AS x ON x.CollectionId = col.Id AND x.IssueKey = c.Cve;
""";

    /// The chooser's stored lists (engine\pro-data\_shared\SI-DataPageLists.ps1): one row per written list and name (Name
    /// NULL = a list written empty). A list without a state row is not written yet. Seeks on the two small tables' keys.
    public const string StoredChoices = """
SELECT s.List, c.Name
FROM sidata.ColumnChoiceState AS s
LEFT JOIN sidata.ColumnChoice AS c ON c.List = s.List;
""";

    /// When the stored lists were last written (and how many there are): the version they are kept under in the web app --
    /// the names are read again only when it moved. One row of a tiny table.
    public const string StoredChoicesVersion = """
SELECT CONCAT(CONVERT(nvarchar(30), MAX(s.BuiltAt), 126), N'|', COUNT(*)) AS V
FROM sidata.ColumnChoiceState AS s;
""";

    /// The stored list keys (sidata.ColumnChoice.List).
    public const string ListCi = "ci", ListIds = "id", ListSources = "source", ListFindings = "finding";

    private const string Ids = "ids AS (SELECT DISTINCT CONVERT(nvarchar(400), j.[value]) AS Owner FROM OPENJSON(@Keys) AS j WHERE j.[value] IS NOT NULL AND j.[value] <> N'')";

    /// The keys and their CI (d: Owner, CiId, Name, DocJson) -- the CI the key is, else (an asset key) the CI that links it.
    public static string CiCte(DataColumnSchema s, RowCiKey kind) =>
        s.Ci ? CiFullExportSql.DocsCte(s.Export, kind == RowCiKey.AssetKey ? CiExportKeys.AssetKey : CiExportKeys.CiId)
             : Ids + ",\nd AS (SELECT i.Owner, CAST(NULL AS nvarchar(64)) AS CiId, CAST(NULL AS nvarchar(400)) AS Name, CAST(NULL AS nvarchar(max)) AS DocJson FROM ids AS i WHERE 1 = 0)";

    /// Each key's CI id, and its document when <paramref name="doc"/>.
    public static string Docs(DataColumnSchema s, RowCiKey kind, bool doc) => "WITH " + CiCte(s, kind) + $"""

SELECT d.Owner, d.CiId, {(doc ? "d.DocJson" : "CAST(NULL AS nvarchar(max)) AS DocJson")}
FROM d;
""";

    /// Each key's identifiers (T = type, V = value) and linked objects (T = '#link'): the collection's identifiers of the key
    /// (and of its CI), the identifiers of every record of its CI, every native id its CI links. Null when nothing can answer.
    public static string? Identifiers(DataColumnSchema s, RowCiKey kind)
    {
        var parts = new List<string>();
        if (s.AssetIdentifiers)
        {
            parts.Add("SELECT i.Owner, ai.IdentifierType AS T, ai.IdentifierValue AS V FROM ids AS i JOIN sidata.AssetIdentifier AS ai ON ai.AssetKey = i.Owner");
            if (s.Ci && kind == RowCiKey.AssetKey)
                parts.Add("SELECT d.Owner, ai.IdentifierType, ai.IdentifierValue FROM d JOIN sidata.AssetIdentifier AS ai ON ai.AssetKey = d.CiId WHERE d.CiId <> d.Owner");
        }
        if (s.Ci && s.Records && s.RecordIdentifiers)
            parts.Add("SELECT d.Owner, ri.IdType, ri.IdValue FROM d JOIN sidata.CiRecord AS r ON r.CiId = d.CiId JOIN sidata.RecordIdentifier AS ri ON ri.RecordKey = r.RecordKey");
        if (s.Ci && s.Links)
            parts.Add("SELECT d.Owner, N'#link', l.NativeId FROM d JOIN sidata.CiLink AS l ON l.CiId = d.CiId");
        if (parts.Count == 0) return null;
        return "WITH " + CiCte(s, kind) + "\n" + string.Join("\nUNION\n", parts) + ";";
    }

    /// The newest object of each (key, source, record, item) of the wanted sources (@Sources: a JSON array).
    public static string? Sources(DataColumnSchema s, RowCiKey kind)
    {
        if (!s.Metadata) return null;
        return "WITH " + CiFullExportSql.MetadataCte(s.Export, kind == RowCiKey.AssetKey ? CiExportKeys.AssetKey : CiExportKeys.CiId, sourceFilter: true) + """

SELECT m.Owner, m.SourceSystem, m.PropertiesJson
FROM m
WHERE m.Rn = 1;
""";
    }

    /// The findings of one collection by id (the clustered key: a seek per id).
    public const string Findings = """
SELECT f.FindingId, f.DetailJson
FROM sidata.Finding AS f
WHERE f.CollectionId = TRY_CONVERT(int, @CollectionId)
  AND f.FindingId IN (SELECT TRY_CONVERT(bigint, j.[value]) FROM OPENJSON(@Ids) AS j);
""";

    /// How many findings of one CVE the per-CVE context is read from (the most risky first); the asset count is exact.
    public const int CveSample = 20;

    /// The per-CVE context: a sample of each CVE's findings (name + row) and the number of distinct affected assets.
    /// IX_Finding_Cve (CollectionId, Cve) answers both; the rows are read for the sample only. <paramref name="issues"/>: the
    /// keys are issues -- a CVE or a configuration id (an exemption, a top finding, a CI finding key). An empty @CollectionId
    /// reads the newest collection.
    /// THE FALLBACK since the context is prepared (<see cref="IssuesStored"/>): read only for a collection the data sync has
    /// not prepared yet (one stored before this release, until its next data sync). Each half of an issue key seeks its own
    /// index -- IX_Finding_Cve, IX_Finding_Config -- and the halves are united by finding id; never "Cve = key OR
    /// ConfigurationId = key" (no index answers an OR across two columns: each key read the whole collection).
    public static string Cves(bool issues)
    {
        // the findings of the key (m: FindingId, AssetKey), one index seek per half
        var cve = "SELECT f.FindingId, f.AssetKey FROM sidata.Finding AS f WHERE f.CollectionId = col.Id AND f.Cve = c.Cve";
        var of = issues
            ? cve + "\n                   UNION\n                   SELECT f.FindingId, f.AssetKey FROM sidata.Finding AS f WHERE f.CollectionId = col.Id AND f.ConfigurationId = c.Cve"
            : cve;
        return $"""
WITH col AS (SELECT COALESCE(TRY_CONVERT(int, NULLIF(@CollectionId, N'')), {PublishedRun.DetailedId}) AS Id),
c AS (SELECT DISTINCT CONVERT(nvarchar(256), j.[value]) AS Cve FROM OPENJSON(@Cves) AS j WHERE j.[value] IS NOT NULL AND j.[value] <> N'')
SELECT c.Cve, x.AssetName, x.DetailJson, n.Assets
FROM c
CROSS JOIN col
CROSS APPLY (SELECT COUNT(DISTINCT m.AssetKey) AS Assets
             FROM ({of}) AS m) AS n
OUTER APPLY (SELECT TOP ({CveSample}) s.AssetName, s.DetailJson
             FROM ({of}) AS m
             JOIN sidata.Finding AS s ON s.CollectionId = col.Id AND s.FindingId = m.FindingId
             ORDER BY s.RiskScore DESC, s.FindingId) AS x;
""";
    }

    // ---- the chooser's lists: THE DATA SYNC runs these (SI-DataPageLists.ps1 carries them word for word -- a test holds
    // them equal) and stores what they answer; the web app reads the stored lists (StoredChoices) and never runs them on a
    // page open (2026-10-20, a small database after a restart: 9.9 s, 6.1 s and up to 60 s one after the other, the CI
    // list failed after 47 s) --------------------------------------------------------------------------------------

    /// The top-level field names of a sample of CI documents.
    public static readonly string CiFieldSample = $"""
SELECT DISTINCT p.[key] AS Name
FROM (SELECT TOP ({DocSample}) c.DocJson FROM sidata.Ci AS c) AS s
CROSS APPLY OPENJSON(CASE WHEN ISJSON(s.DocJson) = 1 AND LEFT(LTRIM(s.DocJson), 1) = N'{"{"}' THEN s.DocJson END) AS p;
""";

    public static string IdentifierTypes(DataColumnSchema s)
    {
        var parts = new List<string>();
        if (s.AssetIdentifiers) parts.Add("SELECT DISTINCT ai.IdentifierType AS Name FROM sidata.AssetIdentifier AS ai");
        if (s.RecordIdentifiers) parts.Add("SELECT DISTINCT ri.IdType AS Name FROM sidata.RecordIdentifier AS ri");
        return parts.Count == 0 ? "" : string.Join("\nUNION\n", parts) + ";";
    }

    /// The flattened property names (<see cref="CiExportFlatten.Metadata"/>) of the newest objects of each source.
    public static readonly string SourcePropertySample = $"""
WITH src AS (SELECT DISTINCT a.SourceSystem FROM sidata.AssetMetadata AS a)
SELECT DISTINCT (LOWER(x.SourceSystem) COLLATE Latin1_General_BIN2) + N'.' + p.[key] + CASE WHEN c.[key] IS NULL THEN N'' ELSE N'.' + c.[key] END AS Name
FROM src
CROSS APPLY (SELECT TOP ({SourceSample}) a.SourceSystem, a.PropertiesJson FROM sidata.AssetMetadata AS a
             WHERE a.SourceSystem = src.SourceSystem AND a.Dropped = 0 ORDER BY a.AssetMetadataId DESC) AS x
CROSS APPLY OPENJSON(CASE WHEN LEFT(LTRIM(x.PropertiesJson), 1) = N'{"{"}' THEN x.PropertiesJson END) AS p
OUTER APPLY (SELECT q.[key] FROM OPENJSON(CASE WHEN p.[type] = 5 THEN p.[value] END) AS q) AS c;
""";

    /// The published Detailed collection's id -- read on its own BEFORE <see cref="FindingFieldSample"/>.
    public static readonly string PublishedDetailedId = $"SELECT {PublishedRun.DetailedId} AS Id;";

    /// The top-level field names of a sample of the published run's findings (@c = <see cref="PublishedDetailedId"/>).
    /// TWO statements on purpose: with the collection resolved inside the same statement (a subquery or an APPLY over
    /// sidata.vPublishedCollection) the plan read the whole collection -- 1.1 M rows at a customer, 23-60 s, a 60-second
    /// timeout on every page that offers the column chooser; with the id as a parameter it seeks 300 rows (~0.1 s).
    public static readonly string FindingFieldSample = $"""
SELECT DISTINCT p.[key] AS Name
FROM (SELECT TOP ({DocSample}) f.DetailJson FROM sidata.Finding AS f WHERE f.CollectionId = @c ORDER BY f.FindingId) AS s
CROSS APPLY OPENJSON(CASE WHEN ISJSON(s.DetailJson) = 1 AND LEFT(LTRIM(s.DetailJson), 1) = N'{"{"}' THEN s.DetailJson END) AS p;
""";
}

/// <summary>
/// PURE: the cells of the extra columns from what the reads returned -- the CI id and document, the identifiers and
/// links, the newest object per source, the finding's row.
/// </summary>
public static class DataColumnFill
{
    /// <paramref name="docs"/>: owner -> (CiId, DocJson); <paramref name="ids"/>: (owner, type, value) with type '#link' for a
    /// linked native id; <paramref name="objects"/>: (owner, source, properties JSON).
    public static Dictionary<string, Dictionary<string, object?>> Ci(IReadOnlyCollection<string> wanted, IEnumerable<string> owners,
        IReadOnlyDictionary<string, (string? CiId, string? DocJson)> docs, IEnumerable<(string Owner, string Type, string Value)> ids,
        IEnumerable<(string Owner, string Source, string? Json)> objects)
    {
        var result = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        var idsBy = ids.ToLookup(x => x.Owner, StringComparer.OrdinalIgnoreCase);
        var objBy = objects.ToLookup(x => x.Owner, StringComparer.OrdinalIgnoreCase);
        var fields = wanted.Select(k => (Key: k, Field: DataColumnKeys.FieldOf(k))).Where(x => x.Field is not null).ToList();
        var types = wanted.Select(k => (Key: k, Type: DataColumnKeys.IdTypeOf(k))).Where(x => x.Type is not null).ToList();
        var props = wanted.Select(k => (Key: k, Source: DataColumnKeys.SourceOf(k))).Where(x => x.Source is not null).ToList();
        foreach (var owner in owners.Where(o => !string.IsNullOrEmpty(o)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
            docs.TryGetValue(owner, out var doc);
            if (wanted.Contains(DataColumnKeys.CiId)) cells[DataColumnKeys.CiId] = doc.CiId;
            if (fields.Count > 0)
            {
                var d = CiExportFlatten.Doc(doc.DocJson);
                foreach (var (key, field) in fields) cells[key] = d.TryGetValue(field!, out var v) ? v : null;
            }
            var mine = idsBy[owner].ToList();
            foreach (var (key, type) in types)
                cells[key] = DataColumnKeys.Join(mine.Where(x => string.Equals(x.Type, type, StringComparison.OrdinalIgnoreCase)).Select(x => (object?)x.Value));
            if (wanted.Contains(DataColumnKeys.Links))
                cells[DataColumnKeys.Links] = DataColumnKeys.Join(mine.Where(x => x.Type == "#link" || string.Equals(x.Type, DataColumnKeys.MemberType, StringComparison.OrdinalIgnoreCase))
                    .Select(x => (object?)x.Value));
            if (props.Count > 0)
            {
                var flat = objBy[owner].Select(o => CiExportFlatten.Metadata(o.Source, o.Json)).ToList();
                foreach (var (key, src) in props)
                    cells[key] = DataColumnKeys.Join(flat.Select(f => f.TryGetValue(src!.Value.Name, out var v) ? v : null));
            }
            result[owner] = cells;
        }
        return result;
    }

    /// A row's fields, looked up in any case (the first spelling wins: a row never fails on two names differing in case).
    private static Dictionary<string, object?> Fold(IReadOnlyDictionary<string, object?> doc)
    {
        var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in doc) d.TryAdd(k, v);
        return d;
    }

    public static Dictionary<string, object?> Finding(IReadOnlyCollection<string> wanted, string? detailJson)
    {
        var d = Fold(CiExportFlatten.Doc(detailJson));
        var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var k in wanted)
        {
            if (DataColumnKeys.FindingFieldOf(k) is { } f) cells[k] = d.TryGetValue(f, out var v) ? v : null;
            else if (DataColumnKeys.ContextOf(k) is { AggregateOnly: false } c) cells[k] = Context(c, d);
        }
        return cells;
    }

    /// A context column of one finding row: the first field it carries (a list as its items), or the words of its set flags.
    public static object? Context(FindingContext c, IReadOnlyDictionary<string, object?> row)
    {
        if (c.Flags is { } flags)
        {
            var on = flags.Where(f => row.TryGetValue(f.Field, out var v) && Truthy(v)).Select(f => f.Words).ToList();
            var known = flags.Any(f => row.TryGetValue(f.Field, out var v) && v is not null);
            return on.Count > 0 ? string.Join(DataColumnKeys.Separator, on) : known ? "no" : null;
        }
        foreach (var f in c.Fields)
            if (row.TryGetValue(f, out var v) && v is not null && !(v is string s && (s.Length == 0 || s == "[]")))
                return v is string text ? Items(text) : v;
        return null;
    }

    private static bool Truthy(object? v) => v switch
    {
        bool b => b,
        double d => d != 0,
        string s => s.Equals("true", StringComparison.OrdinalIgnoreCase) || s == "1",
        _ => false,
    };

    /// <summary>
    /// The cells of ONE finding's context from its PREPARED columns (sidata.Finding, <see cref="ViewStoredColumns.Finding"/>;
    /// <paramref name="row"/>: column -> value) -- the same values <see cref="Finding"/> gives from the finding's row: a
    /// ';'-list as "a; b", the impact of a CVE row as its number.
    /// </summary>
    public static Dictionary<string, object?> FindingStored(IReadOnlyCollection<string> wanted, IReadOnlyDictionary<string, object?> row)
    {
        string? Text(string column) => row.TryGetValue(column, out var v) && v is string s && s.Length > 0 ? s : null;
        var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var k in wanted)
        {
            if (DataColumnKeys.ContextOf(k) is not { AggregateOnly: false } || ViewStoredColumns.FindingRef(k) is not { } e) continue;
            // a number or a date column is the value itself
            if (e.Kind != StoredKind.Text) { cells[k] = row.TryGetValue(e.Column, out var typed) ? ViewStoredColumns.Cell(typed) : null; continue; }
            var text = Text(e.Column);
            if (k == DataColumnKeys.Software && text is null && ViewStoredColumns.FindingRef(ViewStoredColumns.ProductKey) is { } product) text = Text(product.Column);
            cells[k] = text is null ? null : e.Flags.Count > 0 ? text : k == DataColumnKeys.Impact ? ViewStoredColumns.NumberOrText(Items(text)) : Items(text);
        }
        return cells;
    }

    /// <summary>
    /// The cells of a per-CVE / per-issue row from its PREPARED row (sidata.IssueContext; <paramref name="row"/>: column ->
    /// value): each context column as the data sync joined it (distinct, '; '), the affected assets as their first names
    /// and "+ N more" up to the exact number of assets. A key the collection does not hold has empty cells.
    /// </summary>
    public static Dictionary<string, object?> IssueStored(IReadOnlyCollection<string> wanted, IReadOnlyDictionary<string, object?> row)
    {
        var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var k in wanted)
        {
            if (DataColumnKeys.ContextOf(k) is not { } c) continue;
            if (c.Key == DataColumnKeys.Assets)
            {
                var names = row.TryGetValue("AssetNames", out var nv) && nv is string ns && ns.Length > 0 ? ns : null;
                var assets = row.TryGetValue("Assets", out var av) && av is not null ? Convert.ToInt64(av, CultureInfo.InvariantCulture) : 0;
                var shown = row.TryGetValue("AssetNamesShown", out var sv) && sv is not null ? Convert.ToInt64(sv, CultureInfo.InvariantCulture) : 0;
                var more = Math.Max(0, assets - shown);
                cells[k] = names is null ? null : names + (more > 0 ? $" (+ {more.ToString(CultureInfo.InvariantCulture)} more)" : "");
                continue;
            }
            if (ViewStoredColumns.FindingRef(k) is not { Issue.Length: > 0 } e) { cells[k] = null; continue; }
            // a number (the highest over the key's findings) or a date (the earliest) is the value itself
            if (e.Kind != StoredKind.Text) { cells[k] = row.TryGetValue(e.Issue, out var typed) ? ViewStoredColumns.Cell(typed) : null; continue; }
            var text = row.TryGetValue(e.Issue, out var v) && v is string s && s.Length > 0 ? s : null;
            cells[k] = k == DataColumnKeys.Impact ? ViewStoredColumns.NumberOrText(text) : text;
        }
        return cells;
    }

    /// <summary>
    /// The cells of the PREPARED CI columns for one row key. <paramref name="row"/>: the CI's columns (null = no CI answers
    /// the key); <paramref name="own"/>: the collection's own identifiers of the key (an asset key that is not its CI's id
    /// carries identifiers of its own -- they are shown with the CI's).
    /// </summary>
    public static Dictionary<string, object?> CiStored(IReadOnlyCollection<string> wanted, IReadOnlyDictionary<string, object?>? row,
        IReadOnlyCollection<(string Type, string Value)> own)
    {
        var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var k in wanted)
        {
            if (ViewStoredColumns.CiRef(k) is not { } r) continue;
            object? v = null;
            // the CI id of the row is RowCiId (DataColumnSql.CiStored); the field si_ci_id reads the same
            row?.TryGetValue(r.Column == "CiId" ? "RowCiId" : r.Column, out v);
            if (r.Kind != StoredKind.List) { cells[k] = ViewStoredColumns.CiCell(r.Kind, v); continue; }
            var mine = k == DataColumnKeys.Links
                ? own.Where(x => string.Equals(x.Type, DataColumnKeys.MemberType, StringComparison.OrdinalIgnoreCase))
                : own.Where(x => string.Equals(x.Type, DataColumnKeys.IdTypeOf(k), StringComparison.OrdinalIgnoreCase));
            cells[k] = DataColumnKeys.Join(ViewStoredColumns.ListItems(v).Concat(mine.Select(x => x.Value)).Select(x => (object?)x));
        }
        return cells;
    }

    /// A ';'-list or a JSON array of text as "a; b" (one item stays as it is).
    public static string Items(string text)
    {
        var t = text.Trim();
        if (t.StartsWith('[') && t.EndsWith(']'))
        {
            try
            {
                using var doc = JsonDocument.Parse(t);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    return string.Join(DataColumnKeys.Separator, doc.RootElement.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : e.GetRawText())
                        .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase));
            }
            catch (JsonException) { }
        }
        return t.Contains(';') ? string.Join(DataColumnKeys.Separator, t.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase)) : t;
    }

    /// <summary>
    /// The context of a per-CVE row from a sample of its findings: every context column as the DISTINCT values over the
    /// sample, the affected software as "product version (vendor)" items ("chrome 128.0 (google); edge 127.0 (microsoft)"),
    /// and the affected assets as their names, "+ N more" beyond the sample.
    /// </summary>
    public static Dictionary<string, object?> Cve(IReadOnlyCollection<string> wanted, IReadOnlyList<(string? AssetName, string? DetailJson)> sample, long assets)
    {
        var rows = sample.Where(s => s.DetailJson is not null).Select(s => (IReadOnlyDictionary<string, object?>)Fold(CiExportFlatten.Doc(s.DetailJson))).ToList();
        var cells = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var k in wanted)
        {
            if (DataColumnKeys.ContextOf(k) is not { } c) continue;
            if (c.Key == DataColumnKeys.Assets)
            {
                var names = sample.Select(s => s.AssetName).Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                var more = Math.Max(0, assets - names.Count);
                cells[k] = names.Count == 0 ? null : string.Join(", ", names) + (more > 0 ? $" (+ {more.ToString(CultureInfo.InvariantCulture)} more)" : "");
            }
            else if (c.Key == DataColumnKeys.Software)
                cells[k] = SoftwareList(rows) ?? DataColumnKeys.Join(rows.Select(r => Context(c, r)));
            else
                cells[k] = JoinItems(rows.Select(r => Context(c, r)));
        }
        return cells;
    }

    /// "chrome 128.0 (google); edge 127.0 (microsoft)" -- each finding's product, version and vendor, distinct; null when
    /// no finding names a product.
    public static string? SoftwareList(IReadOnlyList<IReadOnlyDictionary<string, object?>> rows)
    {
        var sw = DataColumnKeys.ContextOf(DataColumnKeys.Software)!;
        var vd = DataColumnKeys.ContextOf(DataColumnKeys.Vendor)!;
        var vr = DataColumnKeys.ContextOf(DataColumnKeys.Version)!;
        var items = new List<string>();
        foreach (var r in rows)
        {
            // the row's own "Name Version (Vendor)" list when the data carries it
            if (r.TryGetValue(DataColumnKeys.AffectedSoftwareField, out var whole) && DataColumnKeys.Text(whole) is { Length: > 0 } listed)
            {
                items.AddRange(listed.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                continue;
            }
            if (Context(sw, r) is not { } p || DataColumnKeys.Text(p) is not { Length: > 0 } product) continue;
            var version = DataColumnKeys.Text(Context(vr, r));
            var vendor = DataColumnKeys.Text(Context(vd, r));
            items.Add(product + (version.Length > 0 ? " " + version : "") + (vendor.Length > 0 ? " (" + vendor + ")" : ""));
        }
        var distinct = items.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return distinct.Count == 0 ? null : string.Join(DataColumnKeys.Separator, distinct);
    }

    /// Distinct items over several values, each value possibly a "a; b" list.
    private static object? JoinItems(IEnumerable<object?> values)
    {
        var list = values.Where(v => v is not null).ToList();
        if (list.Count == 0) return null;
        if (list.All(v => v is not string)) return DataColumnKeys.Join(list);
        var items = list.SelectMany(v => DataColumnKeys.Text(v).Split(DataColumnKeys.Separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return items.Count == 0 ? null : string.Join(DataColumnKeys.Separator, items);
    }
}

/// <summary>The SQL implementation over <see cref="IProSql"/>: every statement passes <see cref="SqlGuard"/> first.</summary>
public sealed class DataColumnViews(IProSql sql) : IDataColumnViews
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    /// Told when the chooser's lists could not be read (the web app logs it); the chooser is shown without them.
    public Action<Exception>? OnReadFailed { get; init; }

    // one reference each: a request never reads a half-written entry while another request refreshes it
    private sealed record Cached<T>(DateTime At, T Value);
    private volatile Cached<DataColumnSchema>? _schema;
    private volatile Cached<DataColumnCatalog>? _catalog;

    private async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> Run(string text, IReadOnlyDictionary<string, object?> p, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(text);
        return await ViewTimeout.Run(t => sql.QueryAsync(new SqlQuery(text, p), t), Timeout, ct).ConfigureAwait(false);
    }

    private static bool Flag(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v is not null && Convert.ToInt64(v, CultureInfo.InvariantCulture) != 0;

    public async Task<DataColumnSchema> SchemaAsync(CancellationToken ct)
    {
        if (_schema is { } s && DateTime.UtcNow - s.At < TimeSpan.FromMinutes(5)) return s.Value;
        var rows = await Run(DataColumnSql.Schema, new Dictionary<string, object?>(), ct).ConfigureAwait(false);
        var r = rows.Count > 0 ? rows[0] : new Dictionary<string, object?>();
        var schema = new DataColumnSchema(Flag(r, "HasCi"), Flag(r, "HasLink"), Flag(r, "HasRecord"), Flag(r, "HasMetadata"), Flag(r, "HasAssetIdentifier"),
            Flag(r, "HasRecordIdentifier"), Flag(r, "HasFindingJson")) { CiStored = Flag(r, "HasCiStored"), FindingContext = Flag(r, "HasFindingContext"), Choices = Flag(r, "HasChoices") };
        _schema = new Cached<DataColumnSchema>(DateTime.UtcNow, schema);
        return schema;
    }

    /// How long one answer of <see cref="DataColumnSql.StoredChoicesVersion"/> is trusted (it is asked at most this often).
    public static readonly TimeSpan StateTtl = TimeSpan.FromSeconds(30);
    private volatile Cached<string>? _version;
    private volatile string? _catalogVersion;

    /// The lists a database of this shape offers (and so must have stored before nothing is missing).
    private static IEnumerable<string> Wanted(DataColumnSchema s)
    {
        if (s.Ci) yield return DataColumnSql.ListCi;
        if (s.AssetIdentifiers || s.RecordIdentifiers) yield return DataColumnSql.ListIds;
        if (s.Metadata) yield return DataColumnSql.ListSources;
        if (s.FindingJson) yield return DataColumnSql.ListFindings;
    }

    /// <summary>
    /// The chooser's lists AS THE DATA SYNC WROTE THEM (sidata.ColumnChoice): one small read, kept until the stored lists
    /// move (their version is asked at most every <see cref="StateTtl"/>). The data is never sampled here -- on a cold
    /// database the samples took up to a minute and the page failed. A list not written yet (a new install before its first
    /// data sync, a database before the update) is left out and the catalog says so (<see cref="DataColumnCatalog.Pending"/>);
    /// the shipped CI fields and the known identifier types are always offered. Never throws for the database: a read that
    /// fails or runs out of time answers the catalog without the lists (the request's own cancellation still ends it).
    /// </summary>
    public async Task<DataColumnCatalog> CatalogAsync(CancellationToken ct)
    {
        var fields = CiColumns.Default.Columns.Select(x => x.Field).ToList();
        DataColumnSchema s;
        try { s = await SchemaAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (!ct.IsCancellationRequested) { OnReadFailed?.Invoke(ex); return Build(fields, [], [], [], pending: true); }
        var wanted = Wanted(s).ToHashSet(StringComparer.Ordinal);
        if (wanted.Count == 0) return Build(fields, [], [], [], pending: false);
        if (!s.Choices) return Build(fields, [], [], [], pending: true);
        try
        {
            var version = await VersionAsync(ct).ConfigureAwait(false);
            if (_catalog is { } c && _catalogVersion == version) return c.Value;
            var lists = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            foreach (var r in await Run(DataColumnSql.StoredChoices, new Dictionary<string, object?>(), ct).ConfigureAwait(false))
            {
                var list = ProDataQueries.S(r, "List");
                if (!lists.TryGetValue(list, out var names)) lists[list] = names = new List<string>();
                if (ProDataQueries.SN(r, "Name") is { } n) names.Add(n);
            }
            List<string> Of(string list) => lists.TryGetValue(list, out var x) ? x : new List<string>();
            fields.AddRange(Of(DataColumnSql.ListCi));
            var cat = Build(fields, Of(DataColumnSql.ListIds), Of(DataColumnSql.ListSources), Of(DataColumnSql.ListFindings),
                pending: wanted.Any(w => !lists.ContainsKey(w)));
            // the lists first, their version after: a request in between reads them once more, never old lists as new
            _catalog = new Cached<DataColumnCatalog>(DateTime.UtcNow, cat);
            _catalogVersion = version;
            return cat;
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            OnReadFailed?.Invoke(ex);
            // what was read before stays offered (else the columns without the lists); asked again after StateTtl, never on
            // every page open in a row
            var kept = _catalog?.Value ?? Build(fields, [], [], [], pending: true);
            _catalog = new Cached<DataColumnCatalog>(DateTime.UtcNow, kept);
            _catalogVersion = Unanswered;
            _version = new Cached<string>(DateTime.UtcNow, Unanswered);
            return kept;
        }
    }

    /// The version a read that failed is kept under (never one the database answers).
    private const string Unanswered = "\u0000unanswered";

    private async Task<string> VersionAsync(CancellationToken ct)
    {
        if (_version is { } v && DateTime.UtcNow - v.At < StateTtl) return v.Value;
        var rows = await Run(DataColumnSql.StoredChoicesVersion, new Dictionary<string, object?>(), ct).ConfigureAwait(false);
        var version = rows.Count > 0 ? ProDataQueries.S(rows[0], "V") : "";
        _version = new Cached<string>(DateTime.UtcNow, version);
        return version;
    }

    private static DataColumnCatalog Build(IEnumerable<string> fields, IEnumerable<string> types, IEnumerable<string> props, IEnumerable<string> findings, bool pending) =>
        new(fields.Distinct(StringComparer.Ordinal).OrderBy(f => f, StringComparer.Ordinal).ToList(),
            DataColumnKeys.KnownIdentifierTypes.Union(types, StringComparer.OrdinalIgnoreCase).OrderBy(t => t, StringComparer.OrdinalIgnoreCase).ToList(),
            props.Distinct(StringComparer.Ordinal).OrderBy(p => p, StringComparer.Ordinal).ToList(),
            findings.Distinct(StringComparer.Ordinal).OrderBy(f => f, StringComparer.Ordinal).ToList())
        { Pending = pending };

    public async Task<IReadOnlyDictionary<string, Dictionary<string, object?>>> CiCellsAsync(RowCiKey kind, IReadOnlyList<string> keys, IReadOnlyCollection<string> wanted, CancellationToken ct)
    {
        var owners = keys.Where(k => !string.IsNullOrEmpty(k)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var ci = wanted.Where(DataColumnKeys.IsCi).ToHashSet(StringComparer.Ordinal);
        var result = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        if (kind == RowCiKey.None || owners.Count == 0 || ci.Count == 0) return result;
        var s = await SchemaAsync(ct).ConfigureAwait(false);
        // the PREPARED columns (what a default layout shows) are read from sidata.Ci's columns; everything else -- a column
        // a person added: a source property, a field or an identifier type outside the list -- late, from the documents
        var stored = s.Ci && s.CiStored ? ci.Where(k => ViewStoredColumns.CiRef(k) is not null).ToHashSet(StringComparer.Ordinal) : new HashSet<string>(StringComparer.Ordinal);
        var late = ci.Where(k => !stored.Contains(k)).ToHashSet(StringComparer.Ordinal);
        for (var i = 0; i < owners.Count; i += DataColumnSql.Batch)
        {
            var batch = owners.Skip(i).Take(DataColumnSql.Batch).ToList();
            var cells = batch.ToDictionary(o => o, _ => new Dictionary<string, object?>(StringComparer.Ordinal), StringComparer.OrdinalIgnoreCase);
            if (stored.Count > 0)
            {
                // the owners whose CI's columns are not current (a CI built since the last data sync) are read late too
                var stale = await StoredCiAsync(s, kind, batch, stored, cells, ct).ConfigureAwait(false);
                if (stale.Count > 0) foreach (var (k, v) in await LateCiAsync(s, kind, stale, stored, ct).ConfigureAwait(false)) foreach (var (c, x) in v) cells[k][c] = x;
            }
            if (late.Count > 0) foreach (var (k, v) in await LateCiAsync(s, kind, batch, late, ct).ConfigureAwait(false)) foreach (var (c, x) in v) cells[k][c] = x;
            foreach (var (k, v) in cells) result[k] = v;
        }
        return result;
    }

    /// <summary>
    /// The prepared columns of the batch's CIs into <paramref name="cells"/>: ONE statement by key over sidata.Ci (plus, for
    /// asset keys that show identifiers, the keys' own identifiers) -- no document. Returns the owners that must be read late
    /// instead: their CI's columns are not current, or (a CI id) no CI answers.
    /// </summary>
    private async Task<List<string>> StoredCiAsync(DataColumnSchema s, RowCiKey kind, List<string> batch, HashSet<string> stored,
        Dictionary<string, Dictionary<string, object?>> cells, CancellationToken ct)
    {
        var columns = stored.Select(k => ViewStoredColumns.CiRef(k)!.Column).Where(c => c != "CiId").Distinct(StringComparer.Ordinal).ToList();
        var p = new Dictionary<string, object?> { ["Keys"] = JsonSerializer.Serialize(batch), ["Set"] = ViewStoredColumns.CiSetId };
        var rows = new Dictionary<string, IReadOnlyDictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        var stale = new List<string>();
        foreach (var r in await Run(DataColumnSql.CiStored(s, kind, columns), p, ct).ConfigureAwait(false))
        {
            var owner = ProDataQueries.S(r, "RowKey");
            if (Flag(r, "RowCur")) rows.TryAdd(owner, r); else stale.Add(owner);
        }
        var own = new List<(string Owner, string Type, string Value)>();
        var lists = stored.Any(k => ViewStoredColumns.CiRef(k)!.Kind == StoredKind.List);
        if (kind == RowCiKey.AssetKey && lists && s.AssetIdentifiers)
            foreach (var r in await Run(DataColumnSql.OwnIdentifiers, new Dictionary<string, object?> { ["Keys"] = p["Keys"] }, ct).ConfigureAwait(false))
                own.Add((ProDataQueries.S(r, "Owner"), ProDataQueries.S(r, "T"), ProDataQueries.S(r, "V")));
        var ownBy = own.ToLookup(x => x.Owner, x => (x.Type, x.Value), StringComparer.OrdinalIgnoreCase);
        var none = Array.Empty<(string Type, string Value)>();
        foreach (var owner in batch)
        {
            if (stale.Contains(owner, StringComparer.OrdinalIgnoreCase)) continue;
            rows.TryGetValue(owner, out var row);
            // a CI id no CI answers: left to the late read (it knows what else carries the id)
            if (row is null && kind != RowCiKey.AssetKey) { stale.Add(owner); continue; }
            // the CI's stored lists hold its own identifiers; an asset key that is not its CI's id adds the collection's
            var mine = kind == RowCiKey.AssetKey ? ownBy[owner].ToList() : (IReadOnlyCollection<(string Type, string Value)>)none;
            foreach (var (c, x) in DataColumnFill.CiStored(stored, row, mine)) cells[owner][c] = x;
        }
        return stale;
    }

    /// The late read: the wanted columns from the CI document, the identifier tables and the sources' newest objects, for
    /// these row keys only (three statements at most, each keyed by them).
    private async Task<Dictionary<string, Dictionary<string, object?>>> LateCiAsync(DataColumnSchema s, RowCiKey kind, List<string> batch, HashSet<string> ci, CancellationToken ct)
    {
        var needDoc = ci.Any(k => DataColumnKeys.FieldOf(k) is not null);
        var needIds = ci.Any(k => k == DataColumnKeys.Links || DataColumnKeys.IdTypeOf(k) is not null);
        var sources = ci.Select(DataColumnKeys.SourceOf).Where(x => x is not null).Select(x => x!.Value.Source).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var p = new Dictionary<string, object?> { ["Keys"] = JsonSerializer.Serialize(batch) };
        var docs = new Dictionary<string, (string? CiId, string? DocJson)>(StringComparer.OrdinalIgnoreCase);
        if (s.Ci)
            foreach (var r in await Run(DataColumnSql.Docs(s, kind, needDoc), p, ct).ConfigureAwait(false))
                docs.TryAdd(ProDataQueries.S(r, "Owner"), (ProDataQueries.SN(r, "CiId"), ProDataQueries.SN(r, "DocJson")));
        var ids = new List<(string, string, string)>();
        if (needIds && DataColumnSql.Identifiers(s, kind) is { } idText)
            foreach (var r in await Run(idText, p, ct).ConfigureAwait(false))
                ids.Add((ProDataQueries.S(r, "Owner"), ProDataQueries.S(r, "T"), ProDataQueries.S(r, "V")));
        var objects = new List<(string, string, string?)>();
        if (sources.Count > 0 && DataColumnSql.Sources(s, kind) is { } srcText)
        {
            var ps = new Dictionary<string, object?>(p) { ["Sources"] = JsonSerializer.Serialize(sources) };
            foreach (var r in await Run(srcText, ps, ct).ConfigureAwait(false))
                objects.Add((ProDataQueries.S(r, "Owner"), ProDataQueries.S(r, "SourceSystem"), ProDataQueries.SN(r, "PropertiesJson")));
        }
        return DataColumnFill.Ci(ci, batch, docs, ids, objects);
    }

    public async Task<IReadOnlyDictionary<long, Dictionary<string, object?>>> FindingCellsAsync(string collectionId, IReadOnlyList<long> findingIds, IReadOnlyCollection<string> wanted, CancellationToken ct)
    {
        var result = new Dictionary<long, Dictionary<string, object?>>();
        var fi = wanted.Where(DataColumnKeys.IsFinding).ToList();
        var ids = findingIds.Distinct().ToList();
        if (fi.Count == 0 || ids.Count == 0 || string.IsNullOrEmpty(collectionId)) return result;
        var s = await SchemaAsync(ct).ConfigureAwait(false);
        if (!s.FindingJson) return result;
        // the finding CONTEXT (what a default layout shows) is read from the finding's prepared columns; the finding's row
        // (DetailJson) only when a person added one of its fields (fi.*), or for a collection whose context is not prepared
        // yet (or was prepared for an older list of columns) -- until the data sync reaches it
        var columns = s.FindingContext && fi.All(k => DataColumnKeys.ContextOf(k) is not null) ? FindingColumns(fi) : null;
        for (var i = 0; i < ids.Count; i += DataColumnSql.Batch)
        {
            var batch = ids.Skip(i).Take(DataColumnSql.Batch).ToList();
            var p = new Dictionary<string, object?> { ["CollectionId"] = collectionId, ["Ids"] = JsonSerializer.Serialize(batch) };
            if (columns is not null)
            {
                var rows = await Run(DataColumnSql.FindingsStored(columns), new Dictionary<string, object?>(p) { ["FSet"] = ViewStoredColumns.FindingContextSetId }, ct).ConfigureAwait(false);
                if (rows.Count == 0) continue;
                if (Flag(rows[0], "Prepared"))
                {
                    foreach (var r in rows) result[ProDataQueries.L(r, "FindingId")] = DataColumnFill.FindingStored(fi, r);
                    continue;
                }
                columns = null;   // not prepared: this collection is read from the rows, this batch and the next
            }
            foreach (var r in await Run(DataColumnSql.Findings, p, ct).ConfigureAwait(false))
                result[ProDataQueries.L(r, "FindingId")] = DataColumnFill.Finding(fi, ProDataQueries.SN(r, "DetailJson"));
        }
        return result;
    }

    /// The sidata.Finding columns the wanted context keys read (the software also its product column).
    private static List<string> FindingColumns(IEnumerable<string> wanted)
    {
        var columns = new List<string>();
        foreach (var k in wanted)
        {
            if (ViewStoredColumns.FindingRef(k) is not { } e) continue;
            columns.Add(e.Column);
            if (k == DataColumnKeys.Software && ViewStoredColumns.FindingRef(ViewStoredColumns.ProductKey) is { } product) columns.Add(product.Column);
        }
        return columns.Distinct(StringComparer.Ordinal).ToList();
    }

    public async Task<IReadOnlyDictionary<string, Dictionary<string, object?>>> CveCellsAsync(string collectionId, IReadOnlyList<string> cves, IReadOnlyCollection<string> wanted, CancellationToken ct, bool issues = false)
    {
        var result = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        var fc = wanted.Where(k => DataColumnKeys.ContextOf(k) is not null).ToList();
        var keys = cves.Where(c => !string.IsNullOrWhiteSpace(c)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (fc.Count == 0 || keys.Count == 0 || collectionId is null) return result;
        var s = await SchemaAsync(ct).ConfigureAwait(false);
        if (!s.FindingJson) return result;
        // prepared once per collection by the data sync (sidata.IssueContext, one row per key): the page reads its keys' rows.
        // THE FALLBACK below (a sample of each key's findings, read from their rows) is only for a collection whose context is
        // not prepared yet -- one stored before this release, until the data sync reaches it.
        var issueColumns = s.FindingContext
            ? fc.Select(k => ViewStoredColumns.FindingRef(k)?.Issue).Where(n => !string.IsNullOrEmpty(n)).Select(n => n!).Distinct(StringComparer.Ordinal).ToList()
            : null;
        for (var i = 0; i < keys.Count; i += DataColumnSql.Batch)
        {
            var batch = keys.Skip(i).Take(DataColumnSql.Batch).ToList();
            var p = new Dictionary<string, object?> { ["CollectionId"] = collectionId, ["Cves"] = JsonSerializer.Serialize(batch) };
            if (issueColumns is not null)
            {
                var prepared = await Run(DataColumnSql.IssuesStored(issueColumns), new Dictionary<string, object?>(p) { ["FSet"] = ViewStoredColumns.FindingContextSetId }, ct).ConfigureAwait(false);
                if (prepared.Count > 0 && Flag(prepared[0], "Prepared"))
                {
                    foreach (var r in prepared) result[ProDataQueries.S(r, "Cve")] = DataColumnFill.IssueStored(fc, r);
                    continue;
                }
                issueColumns = null;
            }
            var rows = await Run(DataColumnSql.Cves(issues), p, ct).ConfigureAwait(false);
            foreach (var g in rows.GroupBy(r => ProDataQueries.S(r, "Cve"), StringComparer.OrdinalIgnoreCase))
            {
                var sample = g.Where(r => r.TryGetValue("DetailJson", out var d) && d is not null || r.TryGetValue("AssetName", out var n) && n is not null)
                    .Select(r => (ProDataQueries.SN(r, "AssetName"), ProDataQueries.SN(r, "DetailJson"))).ToList();
                result[g.Key] = DataColumnFill.Cve(fc, sample, ProDataQueries.L(g.First(), "Assets"));
            }
        }
        return result;
    }
}
