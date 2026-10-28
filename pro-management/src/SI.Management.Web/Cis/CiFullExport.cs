using SI.Management.Core.ProData;
using SI.Management.Web.Export;

namespace SI.Management.Web.Cis;

/// One row the page exports: its key (a CI id or an asset key), the CI name the page knows, and the page's own cells.
/// <paramref name="Tail"/>: cells written AFTER the CI document fields (#589: the identifier values and linked objects).
public sealed record CiExportRow(string Key, string? Name, IReadOnlyList<object?> Cells, IReadOnlyList<object?>? Tail = null);

/// <summary>
/// "Export all columns" (the CI pages): two sheets after the page's own filter.
/// <list type="bullet">
/// <item><b>CIs (all fields)</b> -- one row per CI: the page's own columns (At risk), then EVERY field of the CI's
/// document (si_ci_id and si_asset_name first, the rest by name), whatever columns the page shows. Each field is written
/// under the HEADING the grid shows it under (<see cref="FieldHeading"/>, or the view's own heading for a field that is
/// one of its own columns) -- never under its internal field name.</item>
/// <item><b>Full details</b> -- one row per CI, source system, source record and item (the newest object): the CI's key and
/// name, the source, the record, the item, when it was collected, then one column per property the sources reported
/// (<see cref="CiExportFlatten.Metadata"/>: source.property, one level flattened), sorted by name. When full details are
/// off or not loaded the sheet says so in one row.</item>
/// </list>
/// On a view of CIs (keys = CI ids) a third sheet sits between the two: <b>Linked objects</b> -- one row per CI and linked
/// object (the records the correlation joined into the CI): the CI's id and name, the source, the record type, the
/// source's own id and name of it, whether it is the CI's primary record, its state and when the source last saw it.
/// Read in batches of <see cref="BatchSize"/> keys, twice per sheet (the columns first, then the rows), so a large export
/// never holds every document in memory. Capped at Excel's limits; what is left out is said on the Export sheet.
/// </summary>
public static class CiFullExport
{
    public const string FieldsSheet = "CIs (all fields)";
    public const string DetailsSheet = "Full details";
    public const string LinksSheet = "Linked objects";
    public static readonly string[] LinkHeaders = ["CI name", "Source", "Record type", "Source id", "Source name", "Primary record", "State", "Last seen by the source (UTC)"];
    public const int BatchSize = 500;
    public const int MaxColumns = 16_384;
    public static readonly string[] DetailFixed = ["CI name", "Source", "Source record", "Item", "Collection time (UTC)"];
    /// The fields the CI sheet lists first.
    public static readonly string[] FirstFields = ["si_ci_id", "si_asset_name"];

    public const string MetadataTableMissing = "Full details are not in this Pro database yet: the table for them (sidata.AssetMetadata) is missing -- run setup\\Initialize-SIDataSql.ps1 again (it only adds).";
    public const string MetadataOff = "Full details are off: SI_AssetProperties is not 'full', so only the security properties are collected. Set SI_AssetProperties = full; the data sync stores every property of each source after the next asset-properties run.";
    public const string MetadataNotLoaded = "No full details are stored for these CIs yet: the data sync stores them after the next asset-properties run with SI_AssetProperties = full.";

    private static IEnumerable<List<string>> Batches(IReadOnlyList<string> keys)
    {
        for (var i = 0; i < keys.Count; i += BatchSize) yield return keys.Skip(i).Take(BatchSize).ToList();
    }

    /// The CI fields in the sheet's order: <see cref="FirstFields"/>, then the rest by name.
    public static List<string> OrderFields(IEnumerable<string> fields)
    {
        var set = new HashSet<string>(fields, StringComparer.Ordinal);
        foreach (var f in FirstFields) set.Add(f);
        return FirstFields.Concat(set.Where(f => !FirstFields.Contains(f)).OrderBy(f => f, StringComparer.Ordinal)).ToList();
    }

    /// A row's tail cells, exactly <paramref name="n"/> of them.
    private static IEnumerable<object?> TailOf(CiExportRow row, int n) =>
        n == 0 ? Array.Empty<object?>() : (row.Tail ?? Array.Empty<object?>()).Concat(Enumerable.Repeat<object?>(null, n)).Take(n);

    /// The heading a CI document field is written under: the one the grid and the column chooser show for that field as
    /// an extra column ("si_os_name" -> "OS name (CI)") -- also for a field no catalog lists.
    public static string FieldHeading(string field) => DataColumnKeys.Label(DataColumnKeys.Field(field));

    /// <summary>
    /// The headings of the CI sheet's field columns, one per field in the fields' order: <paramref name="fieldHeading"/>
    /// (a view whose own columns are CI fields gives its own headings), else <see cref="FieldHeading"/>; a field without
    /// a heading falls back to <see cref="FieldHeading"/>.
    /// </summary>
    public static List<string> FieldHeadings(IEnumerable<string> fields, Func<string, string?>? fieldHeading = null) =>
        fields.Select(f =>
        {
            var own = fieldHeading?.Invoke(f);
            return string.IsNullOrEmpty(own) ? FieldHeading(f) : own!;
        }).ToList();

    /// <paramref name="fieldHeading"/>: the heading of a CI document field on the CI sheet, when the view has one of its
    /// own for it (null = <see cref="FieldHeading"/>, the heading the grid shows the field under as an extra column).
    public static async Task WriteAsync(XlsxWriter x, ExportInfo info, ICiFullExportViews views, IAssetMetadataViews? metadata, CiExportKeys by,
        string keyHeader, IReadOnlyList<string> pageHeaders, IReadOnlyList<CiExportRow> rows, CancellationToken ct, IReadOnlyList<string>? tailHeaders = null,
        Func<string, string?>? fieldHeading = null)
    {
        var schema = await views.SchemaAsync(ct);
        var keys = rows.Select(r => r.Key).Where(k => k.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var names = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows) if (r.Key.Length > 0 && !names.ContainsKey(r.Key)) names[r.Key] = r.Name;

        // ---- sheet 1: every CI field -------------------------------------------------------------------------------
        var fieldSet = new HashSet<string>(StringComparer.Ordinal);
        if (schema.Ci) foreach (var b in Batches(keys)) foreach (var f in await views.DocFieldsAsync(schema, by, b, ct)) fieldSet.Add(f);
        var fields = schema.Ci ? OrderFields(fieldSet) : new List<string>();
        var room = MaxColumns - pageHeaders.Count;
        if (fields.Count > room)
        {
            info.Notes.Add($"{FieldsSheet}: {fields.Count - room:N0} CI field(s) are left out -- Excel has at most {MaxColumns:N0} columns.");
            fields = fields.Take(Math.Max(0, room)).ToList();
        }
        if (!schema.Ci) info.Notes.Add($"{FieldsSheet}: the CI documents are not in this Pro database yet (the v3 data model arrives with the next data sync); only the page's columns are written.");
        var tail = tailHeaders ?? Array.Empty<string>();
        // the fields under the headings the grid shows them under -- never under their internal names
        var headers = pageHeaders.Concat(FieldHeadings(fields, fieldHeading)).Concat(tail).ToList();
        if (headers.Count == 0) headers.Add(keyHeader);
        using (var s = x.AddSheet(FieldsSheet, headers))
        {
            var byKey = rows.GroupBy(r => r.Key, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
            foreach (var b in Batches(keys))
            {
                var docs = (await views.DocsAsync(schema, by, b, ct)).GroupBy(d => d.Owner, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
                foreach (var key in b)
                {
                    docs.TryGetValue(key, out var doc);
                    if (doc?.Name is { Length: > 0 } n && string.IsNullOrEmpty(names.GetValueOrDefault(key))) names[key] = n;
                    var cells = CiExportFlatten.Doc(doc?.DocJson);
                    foreach (var row in byKey[key])
                    {
                        if (s.RowCount + 2 > XlsxWriter.MaxRows) break;
                        var values = new List<object?>(headers.Count);
                        values.AddRange(row.Cells);
                        foreach (var f in fields)
                        {
                            cells.TryGetValue(f, out var v);
                            if (v is null && f == "si_ci_id") v = doc?.CiId ?? (by == CiExportKeys.CiId ? key : null);
                            if (v is null && f == "si_asset_name") v = doc?.Name;
                            values.Add(v);
                        }
                        values.AddRange(TailOf(row, tail.Count));
                        s.WriteRow(values);
                    }
                }
            }
            // #589: a row tied to no CI (a finding without an asset key) keeps its own columns -- never dropped
            foreach (var row in rows.Where(r => r.Key.Length == 0))
            {
                if (s.RowCount + 2 > XlsxWriter.MaxRows) break;
                var values = new List<object?>(headers.Count);
                values.AddRange(row.Cells);
                values.AddRange(fields.Select(_ => (object?)null));
                values.AddRange(TailOf(row, tail.Count));
                s.WriteRow(values);
            }
            info.Rows.Add((s.Name, s.RowCount));
        }

        // ---- the linked objects: one row per CI and linked object (a view of CIs; written when the CIs have any) ---------
        if (by == CiExportKeys.CiId && schema.Ci && schema.Links)
        {
            SheetWriter? links = null;
            var linksFull = false;
            try
            {
                foreach (var b in Batches(keys))
                {
                    var found = (await views.LinksAsync(schema, b, ct)).ToLookup(l => l.Owner, StringComparer.OrdinalIgnoreCase);
                    foreach (var key in b)
                    {
                        foreach (var l in found[key])
                        {
                            links ??= x.AddSheet(LinksSheet, new[] { keyHeader }.Concat(LinkHeaders).ToList());
                            if (links.RowCount + 2 > XlsxWriter.MaxRows) { linksFull = true; break; }
                            links.WriteRow(new List<object?>
                            {
                                key, ExcelExport.Blank(names.GetValueOrDefault(key)), ExcelExport.Blank(l.Provider), ExcelExport.Blank(l.RecordType), ExcelExport.Blank(l.NativeId),
                                ExcelExport.Blank(l.Name), l.IsPrimary, ExcelExport.Blank(l.State),
                                l.LastSeen is { } seen ? DateTime.SpecifyKind(seen, DateTimeKind.Utc) : null,
                            });
                        }
                    }
                }
                if (links is not null) info.Rows.Add((links.Name, links.RowCount));
            }
            finally { links?.Dispose(); }
            if (linksFull) info.Notes.Add($"{LinksSheet}: the sheet stops at Excel's {XlsxWriter.MaxRows:N0} rows; narrow the filter to get the rest.");
        }

        // ---- sheet 2: the full details per source --------------------------------------------------------------------
        string? note = null;
        var columns = new SortedSet<string>(StringComparer.Ordinal);
        if (!schema.Metadata) note = MetadataTableMissing;
        else foreach (var b in Batches(keys)) foreach (var c in await views.MetadataColumnsAsync(schema, by, b, ct)) columns.Add(c);
        if (note is null && columns.Count == 0)
        {
            var off = false;
            if (metadata is not null)
            {
                try { off = (await metadata.StateAsync(ct)).Data.ModeSetting is { } m && !string.Equals(m, "full", StringComparison.OrdinalIgnoreCase); }
                catch (Exception ex) when (ex is not OperationCanceledException) { off = false; }
            }
            note = off ? MetadataOff : MetadataNotLoaded;
        }
        if (note is not null)
        {
            using var s = x.AddSheet(DetailsSheet, ["Full details"]);
            s.WriteRow(note);
            info.Rows.Add((s.Name, 0));
            info.Notes.Add(DetailsSheet + ": " + note);
            return;
        }
        var fixedHeaders = new[] { keyHeader }.Concat(DetailFixed).ToList();
        var props = columns.ToList();
        var space = MaxColumns - fixedHeaders.Count;
        if (props.Count > space)
        {
            info.Notes.Add($"{DetailsSheet}: {props.Count - space:N0} of {props.Count:N0} source properties are left out (the last by name) -- Excel has at most {MaxColumns:N0} columns.");
            props = props.Take(space).ToList();
        }
        var full = false;
        using (var s = x.AddSheet(DetailsSheet, fixedHeaders.Concat(props).ToList()))
        {
            foreach (var b in Batches(keys))
            {
                var objects = (await views.MetadataAsync(schema, by, b, ct)).ToLookup(o => o.Owner, StringComparer.OrdinalIgnoreCase);
                foreach (var key in b)
                {
                    foreach (var o in objects[key].OrderBy(o => AssetMetadataText.Rank(o.SourceSystem)).ThenBy(o => o.SourceSystem, StringComparer.Ordinal)
                                 .ThenBy(o => o.MemberAssetId, StringComparer.OrdinalIgnoreCase).ThenBy(o => o.ItemName, StringComparer.OrdinalIgnoreCase))
                    {
                        if (s.RowCount + 2 > XlsxWriter.MaxRows) { full = true; break; }
                        var cells = CiExportFlatten.Metadata(o.SourceSystem, o.PropertiesJson);
                        var values = new List<object?>(fixedHeaders.Count + props.Count)
                        {
                            key, ExcelExport.Blank(names.GetValueOrDefault(key)), o.SourceSystem, ExcelExport.Blank(o.MemberAssetId), ExcelExport.Blank(o.ItemName),
                            o.CollectionTime == default ? (object?)null : DateTime.SpecifyKind(o.CollectionTime, DateTimeKind.Utc),
                        };
                        foreach (var p in props) values.Add(cells.TryGetValue(p, out var v) ? v : null);
                        s.WriteRow(values);
                    }
                }
            }
            info.Rows.Add((s.Name, s.RowCount));
        }
        if (full) info.Notes.Add($"{DetailsSheet}: the sheet stops at Excel's {XlsxWriter.MaxRows:N0} rows; narrow the filter to get the rest.");
        info.Add("Full details", "the newest object of each source record, one level flattened (source.property); nested values and lists as JSON text");
    }
}
