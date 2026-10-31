using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace SI.Management.Web.Outputs;

/// <summary>
/// #912 THE STAGING STATUS TABLE (owner 2026-10-27: "if it runs using a scheduler, we need a way to tell their importer that sync
/// is running and when it is ready"; "if servicenow team must create a new third table, you must make that in the gui with
/// schema etc so servicenow team can create it"). PURE.
/// One import set table per install, for both ServiceNow outputs. Every push of an output is one batch, id
/// '&lt;run id&gt;:&lt;output&gt;': a <c>writing</c> row before the first data row, <c>u_si_batch_id</c> on every data row, then
/// ONE end row with the same id -- <c>complete</c>, <c>failed</c> or <c>held</c>. The importer imports a batch only once its
/// complete row exists. The engine writes it (engine\asset-cmdb\_shared\SI-SnowImportSet.ps1, Get-SISnowStagingStatusColumns);
/// this copy of the columns is held to the engine's by a test (through the embedded test pack's 'rest-status' object).
/// Everything here is what the ServiceNow team needs to CREATE the table: its definition, the steps, the REST Insert Multiple
/// record, the import rule -- never a secret.
/// </summary>
public static class ServiceNowStagingStatus
{
    public const string Setting = "SI_DataOut_ServiceNowStagingStatusTable";
    public const string DefaultTable = "u_si_staging_status";
    public const string Label = "SecurityInsight staging status";
    public const string Extends = "sys_import_set_row";
    public const string BatchIdColumn = "u_si_batch_id";
    public const int BatchIdLength = 100;

    /// One column to create: name, label, ServiceNow field type, length, meaning.
    public sealed record Column(string Name, string Label, string Type, int MaxLength, string Meaning);

    /// THE COLUMNS, in order (the engine's Get-SISnowStagingStatusColumns).
    public static readonly IReadOnlyList<Column> Columns =
    [
        new("u_si_batch_id", "Batch id", "string", 100, "The batch: <SecurityInsight run id>:<output>. The same value is on every data row of the batch (u_si_batch_id) and on both status rows of the batch."),
        new("u_si_output", "Output", "string", 40, "Which output the batch belongs to: servicenow-ci (configuration items) or servicenow-vulnerable-item (vulnerable items)."),
        new("u_si_state", "State", "string", 16, "writing (the batch has started), complete (every row was accepted: import it), failed (some rows were not accepted: do not import) or held (stopped before or while sending: do not import); or feedback (information only: the import result SecurityInsight read back for a complete batch -- never a batch state)."),
        new("u_si_connector", "Connector", "string", 100, "The SecurityInsight connector that sent the batch."),
        new("u_si_target_table", "Target staging table", "string", 80, "The staging table the batch's data rows were sent to."),
        new("u_si_source_run", "Source run", "string", 100, "The SecurityInsight run that sent the batch."),
        new("u_si_started_at", "Started at", "glide_date_time", 40, "When the batch started (UTC, yyyy-MM-dd HH:mm:ss)."),
        new("u_si_finished_at", "Finished at", "glide_date_time", 40, "When the batch ended (UTC). Only on the end row."),
        new("u_si_batch_time", "Batch time", "glide_date_time", 40, "When the batch became complete (UTC). Only on a complete row -- the same meaning as u_batch_time in the SQL hand-off."),
        new("u_si_planned_rows", "Planned rows", "integer", 40, "How many data rows the batch sends. On the writing row when it is known before sending; always on the end row."),
        new("u_si_sent_rows", "Sent rows", "integer", 40, "How many data rows ServiceNow accepted. Only on the end row."),
        new("u_si_failed_rows", "Failed rows", "integer", 40, "How many planned data rows were not accepted (or not sent). Only on the end row; 0 on a complete row."),
        new("u_si_import_set_ids", "Import sets", "string", 4000, "The import sets ServiceNow made for the batch's data rows, comma separated (for diagnosis -- select a batch's rows by u_si_batch_id). A long list ends with (+N more)."),
        new("u_si_reason", "Reason", "string", 1000, "Why the batch ended as it did, in plain words."),
        new("u_si_version", "SecurityInsight version", "string", 64, "The SecurityInsight version that sent the batch."),
        // #914 the contract: its version, the mode, the rows per action (the end row), the import result read back (a feedback row)
        new("u_si_contract_version", "Contract version", "string", 16, "The version of the SecurityInsight data contract the batch follows. Columns are only ever added; a rename or a removal comes with a new version."),
        new("u_si_mode", "Mode", "string", 16, "live (a normal sync), resync (an Admin asked for every record again: import it like live) or test (a test batch: never import it)."),
        new("u_si_new_rows", "New rows", "integer", 40, "Rows of the batch with u_action = new. Only on the end row."),
        new("u_si_update_rows", "Update rows", "integer", 40, "Rows with u_action = update. Only on the end row."),
        new("u_si_close_rows", "Close rows", "integer", 40, "Rows with u_action = close. Only on the end row."),
        new("u_si_reopen_rows", "Reopen rows", "integer", 40, "Rows with u_action = reopen. Only on the end row."),
        new("u_si_held_rows", "Held rows", "integer", 40, "Records SecurityInsight holds in this batch (u_action = held, plus first-time records it does not send yet). Only on the end row."),
        new("u_si_out_of_scope_rows", "Out of scope rows", "integer", 40, "Rows with u_action = out_of_scope. Only on the end row."),
        new("u_si_import_inserted", "Import: inserted", "integer", 40, "Your import's result for the batch, as SecurityInsight read it back: rows inserted. Only on a feedback row."),
        new("u_si_import_updated", "Import: updated", "integer", 40, "Rows updated. Only on a feedback row."),
        new("u_si_import_ignored", "Import: ignored", "integer", 40, "Rows ignored, including rows your IRE onBefore script handed over and ignored. Only on a feedback row."),
        new("u_si_import_skipped", "Import: skipped", "integer", 40, "Rows skipped. Only on a feedback row."),
        new("u_si_import_errors", "Import: errors", "integer", 40, "Rows in error. More than 0 raises a SecurityInsight issue. Only on a feedback row."),
        new("u_si_import_pending", "Import: pending", "integer", 40, "Rows not transformed yet when SecurityInsight read the result (read again at the next sync). Only on a feedback row."),
    ];

    /// The column every data row carries (both data staging tables need it).
    public static readonly Column BatchId = new(BatchIdColumn, "Batch id", "string", BatchIdLength,
        "The batch this row belongs to: <SecurityInsight run id>:<output>. Import the row only once the staging status table has a complete row for this batch id.");

    /// THE IMPORT RULE, in one sentence.
    public const string ImportRule = "Import a batch only when the staging status table has a row with u_si_state = complete for its u_si_batch_id: then import exactly the data rows with that u_si_batch_id, each complete batch once, oldest first; never import a failed, held or writing batch.";

    /// The table SecurityInsight writes, from the setting's stored value: no row (null) = the default; a row = its value ('' = none).
    public static string TableOf(bool settingHasRow, string? value) => settingHasRow ? (value ?? "").Trim() : DefaultTable;

    /// The REST Insert Multiple record a staging table needs (data tables: insertMultiple maps by LABEL without it).
    public static string RestInsertMultiple(string table) =>
        $"REST Insert Multiple (System Web Services > REST > REST Insert Multiples, table sys_rest_insert_multiple): a record with Source table = {table}, and a Column mappings row with Content type = application/json and Column mapping = Column name.";

    /// The steps to create the table in the ServiceNow UI (plain words; the team follows them as they are).
    public static IReadOnlyList<string> Steps(string? table)
    {
        var t = string.IsNullOrWhiteSpace(table) ? DefaultTable : table.Trim();
        var name = t.StartsWith("u_", StringComparison.Ordinal) ? t[2..] : t;
        return
        [
            $"In ServiceNow open System Definition > Tables and select New.",
            $"Label: {Label}. Name: {t} (ServiceNow adds the u_ prefix itself -- type {name} if the form adds it). Extends table: Import Set Row ({Extends}). Leave Create module and Create mobile module off.",
            "Add every column of the table below with exactly its column name, type and maximum length (the label is free; the name is what SecurityInsight sends). Save.",
            $"Add a REST Insert Multiple record for {t} with Column mappings = Column name (SecurityInsight writes this table one row at a time, which maps by name; the record keeps it the same if that ever changes).",
            "Give both data staging tables the column u_si_batch_id (string, 100).",
            // #962: the whole role list, the same as "For your ServiceNow team" -- two roles here once left a customer at 403
            "Give the integration user SecurityInsight signs in with every role it needs: import_set_loader and import_transformer (to write this table like the data staging tables), personalize_dictionary (to read the table and its columns -- without it nothing is sent), import_admin (to read the column mapping and the import result), and, for a table of a scoped application, the application's role that gives read and create on it.",
            "On the table's Application Access tab: Accessible from = All application scopes; Can read and Can create on; Allow access to this table via web services on.",
            "No transform map is needed on this table. Your importer reads it: " + ImportRule,
            $"Tell your SecurityInsight admin the table name. If it is not {DefaultTable}, they set {Setting} to it.",
        ];
    }

    /// The table's definition in the format of the ServiceNow schema (JSON) the data staging tables download in
    /// (<see cref="ServiceNowSchema.Kind"/>): the table, how rows arrive, and every field with name, label, type and length.
    public static JsonObject Schema(string? table, string version, DateTime nowUtc)
    {
        var t = string.IsNullOrWhiteSpace(table) ? DefaultTable : table.Trim();
        var fields = new JsonArray();
        foreach (var c in Columns)
        {
            var f = new JsonObject
            {
                ["name"] = c.Name,
                ["label"] = c.Label,
                ["type"] = c.Type switch { "glide_date_time" => "datetime", "integer" => "integer", _ => "string" },
                ["servicenowType"] = c.Type,
                ["maxLength"] = c.MaxLength,
            };
            if (c.Type == "glide_date_time") f["format"] = "yyyy-MM-dd HH:mm:ss in UTC";
            f["key"] = c.Name == BatchIdColumn;
            if (c.Name == "u_si_state") f["allowedValues"] = new JsonArray("writing", "complete", "failed", "held");
            if (c.Name == "u_si_output") f["allowedValues"] = new JsonArray("servicenow-ci", "servicenow-vulnerable-item");
            f["description"] = c.Meaning;
            fields.Add(f);
        }
        return new JsonObject
        {
            ["kind"] = ServiceNowSchema.Kind,
            ["schemaVersion"] = ServiceNowSchema.SchemaVersion,
            ["product"] = "SecurityInsight",
            ["productVersion"] = version,
            ["generatedUtc"] = nowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ["output"] = "staging-status",
            ["label"] = Label,
            ["table"] = new JsonObject
            {
                ["name"] = t,
                ["label"] = Label,
                ["setting"] = Setting,
                ["extends"] = Extends,
                ["columnNames"] = "create every field with exactly the name below: SecurityInsight addresses a column by its name",
            },
            ["target"] = new JsonObject
            {
                ["table"] = "none -- no transform map: your importer reads this table",
                ["importRule"] = ImportRule,
                ["row"] = "One row per state change of a batch: writing, then complete, failed or held, with the same u_si_batch_id.",
            },
            ["transport"] = new JsonObject
            {
                ["api"] = $"POST /api/now/import/{t} (one row per call)",
                ["columnMappings"] = RestInsertMultiple(t),
                ["emptyValues"] = "a column without a value is left out of the row",
                ["datetime"] = "yyyy-MM-dd HH:mm:ss in UTC",
            },
            ["dataTables"] = new JsonObject
            {
                ["column"] = BatchIdColumn,
                ["servicenowType"] = "string",
                ["maxLength"] = BatchIdLength,
                ["note"] = "both data staging tables carry u_si_batch_id on every row",
            },
            ["steps"] = new JsonArray(Steps(t).Select(s => (JsonNode)JsonValue.Create(s)!).ToArray()),
            ["fields"] = fields,
        };
    }

    /// The download's file name.
    public static string FileName(string? table) => "servicenow-schema-" + new string((string.IsNullOrWhiteSpace(table) ? DefaultTable : table.Trim()).Where(ch => char.IsAsciiLetterOrDigit(ch) || ch is '_' or '-').ToArray()) + ".json";

    /// The definition as plain text (the team text and its download carry it).
    public static string PlainText(string? table)
    {
        var t = string.IsNullOrWhiteSpace(table) ? DefaultTable : table.Trim();
        var sb = new StringBuilder();
        sb.Append("Table: ").Append(t).Append(" -- label ").Append(Label).Append(", extends Import Set Row (").Append(Extends).Append(")\n");
        foreach (var c in Columns)
            sb.Append("  ").Append(c.Name).Append("  ").Append(c.Type).Append(c.Type == "string" ? " (" + c.MaxLength.ToString(CultureInfo.InvariantCulture) + ")" : "").Append("  ").Append(c.Label).Append(" -- ").Append(c.Meaning).Append('\n');
        sb.Append("Import rule: ").Append(ImportRule).Append('\n');
        return sb.ToString();
    }
}
