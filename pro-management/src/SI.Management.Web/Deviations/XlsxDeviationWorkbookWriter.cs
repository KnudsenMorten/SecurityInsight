using SI.Management.Web.Export;

namespace SI.Management.Web.Deviations;

/// <summary>
/// The Deviations page's Excel export, on the web app's own <see cref="XlsxWriter"/>: one sheet with the report's columns
/// (<see cref="DeviationReport.Columns"/>), dates as real dates. Registered in Program.cs.
/// </summary>
public sealed class XlsxDeviationWorkbookWriter : IDeviationWorkbookWriter
{
    public byte[] Write(IReadOnlyList<DeviationRow> rows, string sheetName)
    {
        using var ms = new MemoryStream();
        using (var x = new XlsxWriter(ms, "SecurityInsight deviations"))
        {
            x.WriteSheet(sheetName, DeviationReport.Columns, rows.Select(r => (IReadOnlyList<object?>)new object?[]
            {
                DeviationReport.KindLabel(r.Kind), r.Item,   // #287: the workbook is read by people -- the plain kind name r.Scope, r.ShippedDefault, r.Current, r.Reason, r.Owner, r.ChangedBy,
                (object?)r.ChangedAtUtc ?? r.ChangedAt, (object?)r.ExpiresAtUtc ?? r.ExpiresAt, r.Status,
            }));
            x.Complete();
        }
        return ms.ToArray();
    }
}
