using SI.Management.Web.Data;

namespace SI.Management.Web.Deviations;

/// Where the Deviations page reads its rows. Returns the queries it ran, for the page's "query behind this".
public interface IDeviationSource
{
    Task<(DeviationInputs Inputs, IReadOnlyList<string> Queries)> ReadAsync(CancellationToken ct);
}

/// <summary>
/// Reads the deviation report's rows from the Pro database (sql\si-pro-settings.sql). READ-ONLY: every statement is a
/// SELECT. Every read is guarded, so a database that has not had a later schema phase applied yet simply has no rows of
/// that kind (cfg.ChangeLog's Kind column arrived with the documents phase -- before it, every row is a setting).
/// </summary>
public sealed class SqlDeviationSource : IDeviationSource
{
    public const string SettingsSql =
        "IF OBJECT_ID(N'cfg.Setting') IS NOT NULL\nSELECT Name, Scope, ValueJson, KeyVaultSecretName, UpdatedAt, UpdatedBy FROM cfg.Setting;";

    public const string DocumentsSql =
        "IF OBJECT_ID(N'cfg.Document') IS NOT NULL\nSELECT Kind, [Key] AS DocKey, Body, UpdatedAt, UpdatedBy FROM cfg.Document;";

    /// Live templates only (a retired one is no longer shipped); a body only where the report reads it (tier rules).
    public const string TemplatesSql =
        "IF OBJECT_ID(N'cfg.Template') IS NOT NULL\nSELECT Kind, ItemKey, [Version] AS TemplateVersion, CASE WHEN Kind = N'rule' THEN BodyJson END AS BodyJson\nFROM cfg.Template WHERE RetiredAt IS NULL;";

    public const string OverridesSql =
        "IF OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL\nSELECT Kind, ItemKey, State, BodyJson, UpdatedAt, UpdatedBy FROM cfg.ItemOverride WHERE State <> N'inherit';";

    public const string ExemptionsSql =
        "IF OBJECT_ID(N'cfg.Exemption') IS NOT NULL\nSELECT CONVERT(nvarchar(64), ExemptionId) AS ExemptionId, Scope, ReportName, ConfigurationId, Cve, AssetKey, Reason, ExpiresAt, CreatedBy, CreatedAt, RevokedAt\nFROM cfg.Exemption WHERE RevokedAt IS NULL;";

    /// Through EXEC: a batch naming a column the table does not have fails to compile even inside an IF.
    public const string ChangeLogSql =
        "IF COL_LENGTH(N'cfg.ChangeLog', N'Kind') IS NOT NULL\n" +
        "EXEC (N'SELECT ChangeId, Name, Scope, Kind, Action, ChangedAt, ChangedBy, Reason FROM cfg.ChangeLog WHERE Scope NOT IN (N''template'', N''install'')');\n" +
        "ELSE IF OBJECT_ID(N'cfg.ChangeLog') IS NOT NULL\n" +
        "SELECT ChangeId, Name, Scope, CAST(NULL AS nvarchar(16)) AS Kind, Action, ChangedAt, ChangedBy, Reason FROM cfg.ChangeLog;";

    public static readonly string[] All = [SettingsSql, DocumentsSql, TemplatesSql, OverridesSql, ExemptionsSql, ChangeLogSql];

    /// What a query feeds, for the page's one "query behind this" list.
    public static string LabelOf(string sql) =>
        sql == SettingsSql ? "Deviations: settings"
        : sql == DocumentsSql ? "Deviations: exclusions, weights and rules"
        : sql == TemplatesSql ? "Deviations: templates"
        : sql == OverridesSql ? "Deviations: item overrides"
        : sql == ExemptionsSql ? "Deviations: exemptions"
        : sql == ChangeLogSql ? "Deviations: who changed it, when"
        : "Deviations";

    private readonly ISqlExecutor _sql;
    public SqlDeviationSource(ISqlExecutor sql) => _sql = sql;

    public async Task<(DeviationInputs Inputs, IReadOnlyList<string> Queries)> ReadAsync(CancellationToken ct)
    {
        var none = new Dictionary<string, object?>();
        var settings = (await _sql.QueryAsync(SettingsSql, none, ct)).Select(r => new DevSetting(r.Str("Name") ?? "", r.Str("Scope") ?? "",
            r.Str("ValueJson"), r.Str("KeyVaultSecretName"), r.Date("UpdatedAt"), r.Str("UpdatedBy"))).ToList();
        var documents = (await _sql.QueryAsync(DocumentsSql, none, ct)).Select(r => new DevDocument(r.Str("Kind") ?? "", r.Str("DocKey") ?? "",
            r.Str("Body"), r.Date("UpdatedAt"), r.Str("UpdatedBy"))).ToList();
        var templates = (await _sql.QueryAsync(TemplatesSql, none, ct)).Select(r => new DevTemplate(r.Str("Kind") ?? "", r.Str("ItemKey") ?? "",
            r.Str("TemplateVersion"), r.Str("BodyJson"))).ToList();
        var overrides = (await _sql.QueryAsync(OverridesSql, none, ct)).Select(r => new DevOverride(r.Str("Kind") ?? "", r.Str("ItemKey") ?? "",
            r.Str("State") ?? "", r.Str("BodyJson"), r.Date("UpdatedAt"), r.Str("UpdatedBy"))).ToList();
        var exemptions = (await _sql.QueryAsync(ExemptionsSql, none, ct)).Select(r => new DevExemption(r.Str("ExemptionId") ?? "", r.Str("Scope") ?? "",
            r.Str("ReportName"), r.Str("ConfigurationId"), r.Str("Cve"), r.Str("AssetKey"), r.Str("Reason"), r.Date("ExpiresAt"),
            r.Str("CreatedBy"), r.Date("CreatedAt"), r.Date("RevokedAt"))).ToList();
        var log = (await _sql.QueryAsync(ChangeLogSql, none, ct)).Select(r => new DevChange(r.Long("ChangeId") ?? 0, r.Str("Name") ?? "", r.Str("Scope") ?? "",
            r.Str("Kind"), r.Str("Action") ?? "", r.Date("ChangedAt"), r.Str("ChangedBy"), r.Str("Reason"))).ToList();
        return (new DeviationInputs(settings, documents, templates, overrides, exemptions, log), All);
    }
}
