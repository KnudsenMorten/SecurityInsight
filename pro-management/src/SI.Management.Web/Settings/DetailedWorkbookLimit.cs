using SI.Management.Web.Data;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Settings;

/// <summary>
/// THE DETAILED EXCEL WORKBOOK AND ITS SIZE (owner 2026-10-16: "calculate rows and if it is too big gray out option to enable
/// excel detailed in setting"). The Risk Analysis engine writes the detailed workbook only when SI_RA_ExcelExport_Detailed is
/// on AND the run's rows are not more than a workbook can hold here (engine/risk-analysis/_shared/RA-WorkbookExport.ps1,
/// Get-RAWorkbookRowLimit -- THE SAME NUMBER, a test pins both). The Settings page greys the switch out when the newest
/// complete detailed collection is above it, with one plain line; a switch that is on while the results grew past it is shown
/// as on but not applied, with the same line.
/// </summary>
public static class DetailedWorkbookLimit
{
    /// The setting the limit applies to.
    public const string Setting = "SI_RA_ExcelExport_Detailed";

    /// Rows a workbook holds here: two sheets of Excel's 1,048,575 rows (RA-WorkbookExport.ps1 $script:RAWorkbookRowLimit).
    public const long RowLimit = 2_097_150;

    /// The line under the switch when the newest complete detailed collection is above the limit; null = the switch can be used.
    public static string? Unavailable(long? rows) =>
        rows is { } n && n > RowLimit
            ? $"Not available: the detailed results have {Fmt.Int(n)} rows, more than a workbook can hold here. They are in the web app."
            : null;

    /// Whether the switch is stored on (true / "true" / 1) -- the not-applied case.
    public static bool IsOn(string? text) =>
        text is { } t && (t.Trim().Equals("true", StringComparison.OrdinalIgnoreCase) || t.Trim() == "1");
}

/// The rows of the newest complete detailed collection (the sum of its reports' stored rows, sidata.RaReportStatus).
public interface IDetailedWorkbookSize
{
    /// null = not known (no complete detailed collection yet, or the tables are not there).
    Task<long?> ReadRowsAsync(CancellationToken ct);
}

public sealed class SqlDetailedWorkbookSize : IDetailedWorkbookSize
{
    private readonly ISqlExecutor _sql;
    public SqlDetailedWorkbookSize(ISqlExecutor sql) => _sql = sql;

    /// db_datareader only: the published run's Detailed collection and the sum of its reports' stored rows.
    public const string Sql = """
IF OBJECT_ID(N'sidata.RaReportStatus') IS NULL OR OBJECT_ID(N'sidata.Collection') IS NULL
    SELECT CAST(NULL AS bigint) AS [Rows];
ELSE
    SELECT TOP (1) (SELECT SUM(s.StoredRows) FROM sidata.RaReportStatus s WHERE s.Grain = N'Detailed' AND s.CollectionTime = c.CollectionTime) AS [Rows]
    FROM sidata.vPublishedCollection c WHERE c.Kind = N'Detailed';
""";

    public async Task<long?> ReadRowsAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        return rows.FirstOrDefault()?.Long("Rows");
    }
}
