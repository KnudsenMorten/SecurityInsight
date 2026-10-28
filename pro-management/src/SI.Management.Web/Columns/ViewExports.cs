namespace SI.Management.Web.Columns;

/// <summary>
/// THE export choices of a data view (Pages/Shared/_ViewExports.cshtml), together and always visible next to the word
/// Export (owner 2026-10-19: he "could not find export only the page or selected records"): this page · selected rows ·
/// all matching rows, each as CSV or Excel, and every column. Each choice carries exactly the columns chosen, in their
/// order. <paramref name="Page"/>: the view's export handlers answer "this page" (<see cref="ExportChoices.PageOnly"/>);
/// <paramref name="SelectionForm"/>: the id of the form the grid's row checkboxes belong to (the selected-rows export
/// submits it), <paramref name="SelectionStrip"/> the selector of the grid's selection strip (the script enables the
/// selected-rows export while rows are ticked). Words: <see cref="ExportLabels"/>.
/// </summary>
public sealed record ViewExports(string CsvHref, string XlsxHref, string? AllColumnsHref, bool Page = false, string? SelectionForm = null, string? SelectionStrip = null)
{
    /// The links of a page whose handlers are Csv / Xlsx / XlsxAll on <paramref name="handlerLink"/>.
    public static ViewExports Of(Func<string, string> handlerLink, bool allColumns = true) =>
        new(handlerLink("Csv"), handlerLink("Xlsx"), allColumns ? handlerLink("XlsxAll") : null);

    /// The same choices with "this page" and "selected rows" (a paged grid with row selection).
    public ViewExports ForGrid(string selectionForm, string selectionStrip) => this with { Page = true, SelectionForm = selectionForm, SelectionStrip = selectionStrip };

    public string PageCsvHref => ExportChoices.PageLink(CsvHref);
    public string PageXlsxHref => ExportChoices.PageLink(XlsxHref);
}

/// The "this page" export: the export handlers of a paged grid read ONE page (its filters, sort, page number and size)
/// instead of every matching row when the address carries rows=page.
public static class ExportChoices
{
    public const string RowsParam = "rows";
    public const string PageValue = "page";

    public static bool PageOnly(Microsoft.AspNetCore.Http.HttpRequest? request) =>
        request is not null && string.Equals(request.Query[RowsParam], PageValue, StringComparison.OrdinalIgnoreCase);

    public static string PageLink(string handlerHref) => handlerHref + (handlerHref.Contains('?') ? "&" : "?") + RowsParam + "=" + PageValue;
}

/// One page table as Pages/Shared/_DataTable.cshtml renders it.
/// <paramref name="InForm"/>: the table sits inside a form of the page (row selection) -- the chooser (a form of its own) and the
/// export buttons are then
/// rendered by the page outside it.
public sealed record DataTableView(DataTable Table, ViewExports Exports, SI.Management.Web.Cis.ColumnChooser Chooser, bool InForm = false);

/// The selected-row export buttons of a grid's selection strip (Pages/Shared/_SelectedExports.cshtml): they submit the
/// strip's form to the page's Xlsx / Csv handlers with the ticked rows (sel), so the export is of those rows, chosen columns.
public sealed record SelectedExports(string? Form = null);
