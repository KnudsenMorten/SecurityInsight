using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace SI.Management.Web.Export;

/// <summary>
/// "Export to Excel" for a page: the page's handler writes its sheets with an <see cref="XlsxWriter"/>; this class
/// writes them to a temporary file (deleted when the response is done -- the workbook never sits in memory) and returns
/// it as <c>&lt;page&gt;[-&lt;collection&gt;]-&lt;yyyyMMdd-HHmm&gt;Z.xlsx</c>. A failure while writing answers an error,
/// never half a file. Every workbook ends with an "Export" sheet: the page, the filters, the rows per sheet, when, and
/// anything the page could not read.
/// </summary>
public static class ExcelExport
{
    public const string AboutSheet = "Export";

    public static async Task<IActionResult> FileAsync(string page, string? collection, Func<XlsxWriter, ExportInfo, Task> write, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var info = new ExportInfo(page, now);
        var path = Path.Combine(Path.GetTempPath(), "si-export-" + Guid.NewGuid().ToString("N") + ".xlsx");
        var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 64 * 1024, FileOptions.DeleteOnClose);
        try
        {
            using (var x = new XlsxWriter(file, "SecurityInsight " + page, now))
            {
                await write(x, info);
                ct.ThrowIfCancellationRequested();
                // a source on an older collection: the same sentence the pages show, as a note on the Export sheet
                if (SI.Management.Web.Collection.SourceNoteScope.Current is { } sourceNotes)
                    foreach (var line in await SI.Management.Web.Collection.SourceNoteView.ExportLinesAsync(sourceNotes, collection ?? info.Collection, ct))
                        if (!info.Notes.Contains(line)) info.Notes.Add(line);
                // the audit trail (#260): an export records what left the app -- its rows and the filter it was made with
                if (SI.Management.Web.Audit.AuditScope.Current is { } audit)
                {
                    audit.Rows ??= info.Rows.Sum(r => r.Rows);
                    if (info.Items.Count > 0)
                        audit.Filter ??= string.Join("; ", info.Items.Select(i => i.Item + ": " + Convert.ToString(i.Value, CultureInfo.InvariantCulture)));
                }
                info.WriteTo(x);
                x.Complete();
            }
            await file.FlushAsync(ct);
            file.Position = 0;
            return new FileStreamResult(file, XlsxWriter.ContentType) { FileDownloadName = FileName(page, collection ?? info.Collection, now) };
        }
        catch
        {
            await file.DisposeAsync();
            throw;
        }
    }

    /// Writes one sheet and records its row count on the Export sheet.
    public static void Sheet(this XlsxWriter x, ExportInfo info, string name, IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<object?>> rows)
    {
        using var s = x.AddSheet(name, headers);
        foreach (var r in rows) s.WriteRow(r);
        info.Rows.Add((s.Name, s.RowCount));
    }

    /// <c>&lt;page&gt;[-&lt;collection&gt;]-&lt;yyyyMMdd-HHmm&gt;Z.xlsx</c>; the collection is reduced to letters, digits, - and _.
    public static string FileName(string page, string? collection, DateTime utc)
    {
        var c = new StringBuilder();
        foreach (var ch in collection ?? "") if (char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_') c.Append(ch);
        var col = c.Length > 40 ? c.ToString(0, 40) : c.ToString();
        return page + (col.Length > 0 ? "-" + col : "") + "-" + utc.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.xlsx";
    }

    /// A tier label as the number it is ("0".."3"), "Unclassified" stays text.
    public static object? Tier(string? tier) => int.TryParse(tier, NumberStyles.None, CultureInfo.InvariantCulture, out var t) ? t : tier;

    public static object? Blank(string? s) => string.IsNullOrEmpty(s) ? null : s;
}

/// What the Export sheet says about the workbook.
public sealed class ExportInfo(string page, DateTime at)
{
    public string Page { get; } = page;
    public DateTime At { get; } = at;
    /// The collection the export is of, when the page has one (also used in the file name).
    public string? Collection { get; set; }
    public List<(string Item, object? Value)> Items { get; } = new();
    public List<(string Sheet, long Rows)> Rows { get; } = new();
    public List<string> Notes { get; } = new();

    public ExportInfo Add(string item, object? value) { Items.Add((item, value)); return this; }
    /// A filter of the page: no value = "(all)".
    public ExportInfo Filter(string item, string? value) => Add(item, string.IsNullOrEmpty(value) ? "(all)" : value);

    internal void WriteTo(XlsxWriter x)
    {
        using var s = x.AddSheet(ExcelExport.AboutSheet, new[] { "Item", "Value" });
        s.WriteRow("Page", Page);
        s.WriteRow("Exported (UTC)", At);
        if (Collection is not null) s.WriteRow("Collection", Collection);
        foreach (var (k, v) in Items) s.WriteRow(k, v);
        foreach (var (sheet, rows) in Rows) s.WriteRow("Rows: " + sheet, rows);
        foreach (var n in Notes) s.WriteRow("Note", n);
        s.WriteRow("Source", "SecurityInsight Pro");
    }
}
