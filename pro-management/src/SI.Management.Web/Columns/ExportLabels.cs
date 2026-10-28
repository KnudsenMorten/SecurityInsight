namespace SI.Management.Web.Columns;

/// <summary>
/// THE words of the export buttons on every data view -- one place, so every view says the same (owner 2026-10-11: "also
/// include the word All in he export buttn so peope knows it exports all rows"). The all-rows exports take every row
/// matching the current filters (not only the page shown); the selected-row exports take the ticked rows; both carry
/// exactly the columns chosen. "Export all columns" is about COLUMNS: every column the view can offer, for the same rows.
/// A guard test holds every data view's all-rows labels to <see cref="AllRowsMarker"/>.
/// </summary>
public static class ExportLabels
{
    public const string AllRowsMarker = "all rows";

    public const string AllRowsCsv = "Export all rows (CSV)";
    public const string AllRowsExcel = "Export all rows to Excel";
    public const string SelectedRowsExcel = "Export selected rows to Excel";
    public const string SelectedRowsCsv = "Export selected rows (CSV)";
    public const string AllColumns = "Export all columns";
    /// The action bar's export on a view whose rows stand for several findings each (a CVE, a CI, a service): the findings
    /// behind the selected rows, not the rows themselves.
    public const string SelectedRowsFindings = "Export the findings of the selected rows";

    /// "Export this page": the rows the page shows now (owner 2026-10-19).
    public const string PageRowsCsv = "Export this page (CSV)";
    public const string PageRowsExcel = "Export this page to Excel";
    public const string PageRowsHint = "The rows shown on this page (its filters, sort and page), with the columns you chose";
    /// The hint a selected-rows export carries while no row is ticked.
    public const string SelectedRowsNone = "Tick rows in the table first";

    public const string AllRowsCsvHint = "Every row matching the current filters (not only this page), with the columns you chose, as CSV";
    public const string AllRowsExcelHint = "Every row matching the current filters (not only this page), with the columns you chose, as an Excel workbook";
    public const string SelectedRowsHint = "The ticked rows, with the columns you chose";
    public const string AllColumnsHint = "Every row matching the current filters with EVERY column this view can offer -- for a view of CIs every CI field, identifier, linked object and a Full details sheet with every property each source reported";

    /// The labels the old buttons had -- a guard test refuses them on every data view.
    public static readonly IReadOnlyList<string> Retired = ["Export (CSV)", "Export to Excel", "Export selected to Excel", "Export selected (CSV)", "Export this view (CSV)"];
}
