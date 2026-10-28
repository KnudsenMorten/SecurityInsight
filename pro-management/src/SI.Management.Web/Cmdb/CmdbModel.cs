using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Cmdb;

/// <summary>
/// WHICH CMDB IS AUTHORITATIVE (#256). One source at a time, chosen by the setting SIWeb_CmdbSource (a web-app setting,
/// scope 'engine:management-web', SI when unset). Every source fills the SAME tables (cfg.CmdbService /
/// cfg.CmdbServiceAsset, its rows stamped with Source); the resolver (cfg.vCmdbAssetService) reads only the rows of the
/// authoritative source. Switching never copies, merges or removes anything.
/// </summary>
public static class CmdbSources
{
    public const string Setting = "SIWeb_CmdbSource";
    /// SecurityInsight owns the CMDB: services are added, edited and retired on the CMDB page; links on the service map.
    public const string SI = "SI";
    /// An external CMDB imported from a CSV in the v2.2 CMDB.csv format (uploaded, or read from a path on a schedule).
    public const string ExternalCsv = "External-CSV";
    /// An external CMDB pulled from ServiceNow through the connector.
    public const string ExternalConnector = "External-Connector";
    public static readonly IReadOnlyList<string> All = [SI, ExternalCsv, ExternalConnector];

    public static bool IsKnown(string? s) => s is not null && All.Contains(s, StringComparer.Ordinal);
    /// External sources are read-only in SecurityInsight: their services and links are edited in the source.
    public static bool IsReadOnly(string source) => source != SI;

    public static string Label(string source) => source switch
    {
        SI => "SecurityInsight (SI-homed CMDB)",
        ExternalCsv => "External CMDB -- CSV file",
        ExternalConnector => "External CMDB -- ServiceNow connector",
        _ => source,
    };

    /// The source a setting row names (the JSON value), SI when none or not a known source.
    public static string FromSettingValue(string? valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson)) return SI;
        try
        {
            using var d = JsonDocument.Parse(valueJson);
            return d.RootElement.ValueKind == JsonValueKind.String && IsKnown(d.RootElement.GetString()) ? d.RootElement.GetString()! : SI;
        }
        catch (JsonException) { return SI; }
    }

    /// The catalog entry: shown on the Settings page like every web-app setting, changed on the CMDB source page.
    public static readonly CatalogSetting Catalog = new()
    {
        Name = Setting, Label = "CMDB source", Group = "Connectors & CMDB", Type = "enum", Values = All, Engines = new[] { "management-web" },
        Edition = "pro", WebOnly = true, Default = JsonDocument.Parse("\"SI\"").RootElement.Clone(), Card = "CMDB",
        Description = "Which CMDB is authoritative for business services and the assets that belong to them: SI (SecurityInsight owns the CMDB), External-CSV (a CMDB.csv in the v2.2 format) or External-Connector (ServiceNow through the connector).",
        Purpose = "Chooses the one CMDB SecurityInsight reads its business services from -- its own, a CSV export, or ServiceNow.",
        DefaultText = "SI: SecurityInsight owns the CMDB; services are added on the CMDB page and assets linked on the service map",
        Effect = "The Services view, risk weighting, departments and the data sync read the services of this source only. The other sources' services stay stored, unused; nothing is copied or merged. With an external source the CMDB page and the service map are read-only: changes are made in the source and arrive with its next import.",
        WhenToChange = "Once, when you decide where your CMDB lives. Change it on the CMDB source page, which explains what happens before anything is saved.",
    };
}

/// One service. Number: SVC-0001 for an SI-homed service; the source's own id for an external one.
public sealed record CmdbService(int ServiceId, string Source, string Number, string? ExternalId, string Name, string? Description, string? Owner, string? OwnerMail,
    string? Criticality, string? DataSensitivity, string? Environment, string? Department, string? ExtraJson, DateTime? CreatedAt, string? CreatedBy,
    DateTime? UpdatedAt, string? UpdatedBy, DateTime? RetiredAt, string? RetiredBy, string? RetireReason, long Version, long Assets)
{
    public bool Retired => RetiredAt is not null;

    /// The other CMDB.csv columns (kept verbatim), as name -> value.
    public IReadOnlyList<KeyValuePair<string, string>> Extra()
    {
        if (string.IsNullOrWhiteSpace(ExtraJson)) return Array.Empty<KeyValuePair<string, string>>();
        try
        {
            using var d = JsonDocument.Parse(ExtraJson);
            return d.RootElement.ValueKind != JsonValueKind.Object ? Array.Empty<KeyValuePair<string, string>>()
                : d.RootElement.EnumerateObject().Select(p => new KeyValuePair<string, string>(p.Name, p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.GetRawText())).ToList();
        }
        catch (JsonException) { return Array.Empty<KeyValuePair<string, string>>(); }
    }
}

/// What the CMDB page's form posts for a new or changed SI-homed service.
public sealed record CmdbServiceInput(string Name, string? Description, string? Owner, string? OwnerMail, string? Criticality, string? DataSensitivity,
    string? Environment, string? Department)
{
    public CmdbServiceInput Normalized() => new(Name.Trim(), N(Description), N(Owner), N(OwnerMail), CmdbVocabulary.Canonical(CmdbVocabulary.Criticalities, N(Criticality)),
        CmdbVocabulary.Canonical(CmdbVocabulary.Sensitivities, N(DataSensitivity)), N(Environment), N(Department));

    private static string? N(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// The reasons a service is refused (empty = accepted). The same limits as a CMDB.csv row.
    public IReadOnlyList<string> Validate()
    {
        var why = new List<string>();
        if (string.IsNullOrWhiteSpace(Name)) why.Add("a service needs a name");
        else if (Name.Trim().Length > CmdbVocabulary.MaxName) why.Add($"the name is longer than {CmdbVocabulary.MaxName} characters");
        void Len(string? v, int max, string what) { if (v is not null && v.Trim().Length > max) why.Add($"{what} is longer than {max} characters"); }
        Len(Description, CmdbVocabulary.MaxDescription, "the description");
        Len(Owner, CmdbVocabulary.MaxOwner, "the owner");
        Len(Environment, CmdbVocabulary.MaxEnvironment, "the environment");
        Len(Department, CmdbVocabulary.MaxDepartment, "the department");
        if (!string.IsNullOrWhiteSpace(OwnerMail) && !CmdbVocabulary.IsMail(OwnerMail.Trim())) why.Add($"'{OwnerMail.Trim()}' is not an e-mail address");
        if (!string.IsNullOrWhiteSpace(Criticality) && !CmdbVocabulary.Criticalities.Contains(CmdbVocabulary.Canonical(CmdbVocabulary.Criticalities, Criticality.Trim())!))
            why.Add("criticality is one of: " + string.Join(", ", CmdbVocabulary.Criticalities));
        if (!string.IsNullOrWhiteSpace(DataSensitivity) && !CmdbVocabulary.Sensitivities.Contains(CmdbVocabulary.Canonical(CmdbVocabulary.Sensitivities, DataSensitivity.Trim())!))
            why.Add("data sensitivity is one of: " + string.Join(", ", CmdbVocabulary.Sensitivities));
        return why;
    }
}

/// The words risk weighting understands, and the limits every writer applies (the CSV import, the form, the database).
public static class CmdbVocabulary
{
    public static readonly IReadOnlyList<string> Criticalities = ["Critical", "High", "Medium", "Low"];
    public static readonly IReadOnlyList<string> Sensitivities = ["Restricted", "Confidential", "Internal", "Public"];
    public const int MaxNumber = 64, MaxName = 256, MaxDescription = 2000, MaxOwner = 256, MaxMail = 256, MaxEnvironment = 64, MaxDepartment = 128, MaxExtra = 2000;

    /// The canonical spelling when the value matches one (case-insensitive), else the value as written.
    public static string? Canonical(IReadOnlyList<string> words, string? value) =>
        value is null ? null : words.FirstOrDefault(w => string.Equals(w, value, StringComparison.OrdinalIgnoreCase)) ?? value;

    public static bool IsMail(string s) => s.Length <= MaxMail && System.Text.RegularExpressions.Regex.IsMatch(s, @"^[^@\s;,]+@[^@\s;,]+\.[^@\s;,]+$");

    /// Rank for "the most critical service wins": Critical 1 .. Low 4, anything else 9 (the same CASE as cfg.vCmdbService).
    public static int Rank(string? criticality) => criticality switch { "Critical" => 1, "High" => 2, "Medium" => 3, "Low" => 4, _ => 9 };
}

/// SVC-0001: four digits, more when the sequence passes 9999 -- the same expression as the SQL that assigns it.
public static class CmdbNumbers
{
    public const string Prefix = "SVC-";
    public static string Format(int sequence) => Prefix + (sequence < 10000 ? sequence.ToString("D4", CultureInfo.InvariantCulture) : sequence.ToString(CultureInfo.InvariantCulture));
}

/// One asset card on the service map: name, kind, tier, weighted risk (the newest collection) and its current services.
public sealed record MapAsset(string AssetKey, string AssetName, string? AssetKind, string Tier, double? WeightedRisk, int Services, string? ServiceNumbers);

/// The service map's asset filter. Every value is checked (ProDataFilters) before it reaches SQL.
public sealed record MapFilter
{
    public string? Kind { get; init; }
    public string? Tier { get; init; }
    public string? Text { get; init; }
    /// Only assets that belong to no service of the authoritative CMDB.
    public bool UnlinkedOnly { get; init; }
    /// Only assets linked to a service of this department (services carry their department).
    public string? Department { get; init; }
    /// #855 M18: the CI lifecycle of the assets shown (<see cref="SI.Management.Core.ProData.LifecycleFilter.Key"/>: "active" --
    /// THE DEFAULT --, "not_seen", "retired", "all", or several ','-joined). An asset's lifecycle is its CI's (the CI id = the
    /// asset key, else the CI that carries it as a linked object); an asset no CI carries is active.
    public string Lifecycle { get; init; } = SI.Management.Core.ProData.LifecycleFilter.Active.Key;
}

public sealed record CmdbImportResult(string Outcome, string? Message, long? ImportId, int ServicesAdded, int ServicesUpdated, int ServicesRetired,
    int ServicesSkipped, int ServicesUnchanged, int LinksAdded, int LinksRemoved, int LinksRejected, string? RejectedJson)
{
    public bool Imported => Outcome == "Imported";
}

public sealed record CmdbImportRow(long ImportId, string Source, string Kind, string? Origin, DateTime? ImportedAt, string ImportedBy, string Outcome, string? Message,
    int ServicesAdded, int ServicesUpdated, int ServicesRetired, int ServicesSkipped, int LinksAdded, int LinksRemoved, int LinksRejected, string? RejectedJson);
