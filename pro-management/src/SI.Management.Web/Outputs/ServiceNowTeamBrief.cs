using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Outputs;

/// <summary>
/// #903 "FOR YOUR SERVICENOW TEAM" (PURE): what the customer's ServiceNow team must still do for the ServiceNow data out,
/// in plain words, generated from the connector, both outputs' Import Set tables and the newest check of each
/// (cfg.ServiceNowCheck) -- the roles still missing (each with what it is for), each staging table (does it exist, does it
/// extend Import Set Row, the columns still missing or too short), REST Insert Multiple with column mapping = column name,
/// 'SecurityInsight' as a discovery_source choice when CIs are sent, the transform maps, the instance reachable from Azure.
/// A Copy button and a text download hand it to the team.
/// NEVER a secret, a secret value, a token, a header -- not even a Key Vault secret NAME (the team does not need them; a
/// test holds this). Texts the engine wrote are not copied in: each line is this class's own words.
/// </summary>
public static class ServiceNowTeamBrief
{
    /// One thing for the team: done (true), still to do (false), not known yet (null).
    public sealed record Line(string Section, string Key, bool? Done, string Text);

    /// One output as the page knows it: its table setting's value, its newest check, the schema comparison's lines, on or off.
    public sealed record OutputState(ServiceNowOutputs.Info Info, string? Table, SnowCheckRow? Latest, IReadOnlyList<SchemaLine> Schema, bool On);

    private static JsonObject Obj(string? json)
    {
        try { return JsonNode.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json) as JsonObject ?? new JsonObject(); }
        catch (JsonException) { return new JsonObject(); }
    }

    /// The instance address when it is in the connector's settings (an https address -- not a secret); else null.
    public static string? Instance(ConnectorRow? c)
    {
        var s = Obj(c?.SettingsJson);
        var v = s.FirstOrDefault(p => string.Equals(p.Key, "instance", StringComparison.OrdinalIgnoreCase)).Value;
        return v is JsonValue j && j.TryGetValue<string>(out var t) && ServiceNowInstanceUrl.Validate(t).Url is { } url ? url : null;
    }

    /// #912 One table the ServiceNow team creates, as the section shows it: its name (null = not agreed yet), label, what it
    /// extends, every column (name, label, ServiceNow type, length, meaning), where its definition downloads, a note.
    public sealed record TableDef(string Key, string Title, string? Table, string Label, string Extends, IReadOnlyList<ServiceNowStagingStatus.Column> Columns, string? Download, string Note);

    /// PURE. A data staging table from its ServiceNow schema (<see cref="ServiceNowSchema.Build"/>: the columns in force + u_si_batch_id).
    public static TableDef TableFromSchema(string key, string title, string? table, JsonObject schema, string? download)
    {
        static string S(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
        static int I(JsonNode? n) => n is JsonValue v && v.TryGetValue<int>(out var i) ? i : 0;
        var cols = (schema["fields"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
            .Select(f => new ServiceNowStagingStatus.Column(S(f["name"]), S(f["label"]), S(f["servicenowType"]) is { Length: > 0 } t ? t : "string", I(f["maxLength"]), S(f["description"])))
            .Where(x => x.Name.Length > 0).ToList();
        return new TableDef(key, title, string.IsNullOrWhiteSpace(table) ? null : table.Trim(), title, ServiceNowStagingStatus.Extends, cols, download,
            "Create every column with exactly this name (the label is free) and at least this length. " + ServiceNowStagingStatus.RestInsertMultiple(string.IsNullOrWhiteSpace(table) ? "the table" : table.Trim()));
    }

    /// PURE. The staging status table as the section shows it (<paramref name="table"/>: the table in force, '' = none set).
    public static TableDef StatusTableDef(string table, string? download) =>
        new("staging-status", "Staging status table", string.IsNullOrWhiteSpace(table) ? ServiceNowStagingStatus.DefaultTable : table.Trim(), ServiceNowStagingStatus.Label,
            ServiceNowStagingStatus.Extends, ServiceNowStagingStatus.Columns, download,
            "One row per state change of a batch: writing, then complete, failed or held, with the same u_si_batch_id. " + ServiceNowStagingStatus.ImportRule);

    /// #912: the staging status table's lines (<paramref name="statusTable"/> = the table in force; '' = none set).
    public static IReadOnlyList<Line> StatusLines(string statusTable, IReadOnlyList<OutputState> outputs)
    {
        const string S = "Staging status table (tells your importer when a batch is complete)";
        var lines = new List<Line>();
        var t = (statusTable ?? "").Trim();
        if (t.Length == 0)
        {
            lines.Add(new(S, "status-table-set", false, $"No staging status table is set: SecurityInsight sends the rows without it, and nothing tells your importer when a push is complete. Create {ServiceNowStagingStatus.DefaultTable} (below), then your SecurityInsight admin sets {ServiceNowStagingStatus.Setting}."));
            lines.Add(new(S, "status-import-rule", null, "Once it is there: " + ServiceNowStagingStatus.ImportRule));
            return lines;
        }
        var facts = outputs.Select(o => o.Latest?.Facts).Where(f => f is { StatusChecked: true } && string.Equals(f.StatusTable, t, StringComparison.OrdinalIgnoreCase)).Select(f => f!).ToList();
        bool? exists = facts.Any(f => f.StatusExists == false) ? false : facts.Any(f => f.StatusExists == true) ? true : null;
        lines.Add(new(S, "status-table-exists", exists, $"The table {t} exists (label {ServiceNowStagingStatus.Label}, extends Import Set Row)." + (exists == false ? " It does not exist yet: nothing is sent until it is there. Create it from the definition below." : "")));
        var missing = facts.SelectMany(f => f.StatusMissing).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        bool? cols = exists != true ? null : missing.Count > 0 ? false : facts.Any(f => f.StatusExists == true) ? true : null;
        lines.Add(new(S, "status-table-columns", cols, cols == false ? $"{t} still needs: {string.Join(", ", missing)} -- nothing is sent until they are there." : $"{t} has every column of the staging status table."));
        var noBatchId = outputs.Where(o => o.Schema.Any(l => string.Equals(l.Column, ServiceNowStagingStatus.BatchIdColumn, StringComparison.OrdinalIgnoreCase) && l.Kind == "missing")).Select(o => o.Table ?? o.Info.Label).ToList();
        bool? batchCol = noBatchId.Count > 0 ? false : outputs.Any(o => o.Schema.Count > 0) ? true : null;
        lines.Add(new(S, "status-batch-id", batchCol, "Both data staging tables have the column u_si_batch_id (string, 100) -- every data row carries its batch." + (noBatchId.Count > 0 ? " Missing in: " + string.Join(", ", noBatchId) + "." : "")));
        lines.Add(new(S, "status-import-rule", null, "Your importer: " + ServiceNowStagingStatus.ImportRule));
        lines.Add(new(S, "status-retention", null, "Your Import Set cleanup keeps at least the rows of the two newest complete batches of each output, and the staging status rows as long as the data rows. SecurityInsight never deletes anything in ServiceNow."));
        return lines;
    }

    public static IReadOnlyList<Line> Build(ConnectorRow? c, IReadOnlyList<OutputState> outputs, string? statusTable = null)
    {
        var lines = new List<Line>();
        var facts = outputs.Select(o => o.Latest?.Facts).Where(f => f is not null).Select(f => f!).ToList();
        bool Any(Func<SnowCheckFacts, bool> p) => facts.Any(p);

        // ---- the roles of the integration user, each with what it is for
        const string R = "Roles of the integration user SecurityInsight signs in with";
        lines.Add(new(R, "role-send", null, "import_set_loader and import_transformer -- to send rows through the Import Set API (insertMultiple). Shown on the first send."));
        bool? cols = Any(f => f.ConnectionKind == "role" || f.ColumnsRole.Length > 0) ? false : Any(f => f.ColumnsRead) ? true : null;
        lines.Add(new(R, "role-columns", cols, "personalize_dictionary -- to read the staging table and its columns, so SecurityInsight checks them before it sends." +
            (cols == false ? " Missing today: ServiceNow refuses the read with 403 \"unauthorized to access table: sys_db_object\"." : "")));
        bool? map = Any(f => f.MappingRole.Length > 0) ? false : Any(f => f.Mapping is "name" or "label") ? true : null;
        lines.Add(new(R, "role-mapping", map, "import_admin (optional) -- to read the REST Insert Multiple column mapping, so SecurityInsight can tell whether it is right." +
            (map == false ? " Missing today: the mapping cannot be read; without the role it is not checked." : "")));

        // ---- per staging table
        foreach (var o in outputs)
        {
            var f = o.Latest?.Facts;
            var sec = "Staging table for " + o.Info.Label + (o.On ? "" : " (this output is switched off in SecurityInsight)");
            var t = string.IsNullOrWhiteSpace(o.Table) ? null : o.Table.Trim();
            if (t is null) { lines.Add(new(sec, "table-name", false, "The table name is not agreed yet -- agree it with your SecurityInsight admin (for example " + (o.Info.Output == "servicenow-ci" ? "u_si_ci_import" : "u_si_vulnerable_item_import") + ").")); continue; }
            lines.Add(new(sec, "table-exists", f?.TableExists, $"The table {t} exists on the instance." + (f?.TableExists == false ? " It does not exist yet: create it from the ServiceNow schema (JSON) your SecurityInsight admin downloads from the connector page." : f?.TableExists is null ? " Not known until SecurityInsight's check reads it." : "")));
            lines.Add(new(sec, "table-importset", f?.ImportSet, $"{t} extends Import Set Row (sys_import_set_row) -- the Import Set API sends only to an import set table." + (f?.ImportSet == false ? " It does not today." : "")));
            var red = o.Schema.Where(l => l.Level == "red" && l.Kind is "missing" or "short").ToList();
            if (f?.ColumnsRead == true)
                lines.Add(new(sec, "table-columns", red.Count == 0, red.Count == 0 ? $"{t} has every column SecurityInsight sends, long enough."
                    : $"{t} still needs: " + string.Join("; ", red.Select(l => l.Kind == "missing" ? l.Column + " (missing)" : l.Column + " (too short)")) + "."));
            else lines.Add(new(sec, "table-columns", null, $"{t} has every column SecurityInsight sends, at least as long as the schema says -- checked once the columns can be read."));
            bool? byName = f is null || f.Mapping.Length == 0 || f.Mapping == "unknown" ? null : f.Mapping == "name";
            lines.Add(new(sec, "rest-insert-multiple", byName, $"A REST Insert Multiple record (sys_rest_insert_multiple) for {t} with Column mappings = Column name. By default ServiceNow matches by label, and the rows land empty."));
            lines.Add(new(sec, "transform", null, $"A transform map from {t} to " + (ServiceNowTeamPack.TargetOf(o.Info.Output)?.Intended ?? "its target") + " -- your own; SecurityInsight does not read it."));
        }

        // ---- #912 the staging status table (null = not passed: the section predates it)
        if (statusTable is not null) lines.AddRange(StatusLines(statusTable, outputs));

        // ---- the CMDB: SecurityInsight as a discovery source, when the transform writes CIs
        if (outputs.Any(o => o.Info.Output == "servicenow-ci" && (o.On || !string.IsNullOrWhiteSpace(o.Table))))
            lines.Add(new("CMDB", "discovery-source", null, "'SecurityInsight' as a choice on cmdb_ci.discovery_source, if your transform writes CIs through Identification and Reconciliation (IRE refuses a payload from an unregistered source)."));

        // ---- the network
        var down = facts.FirstOrDefault(f => f.ConnectionKind is "dns" or "tls" or "network" or "timeout");
        bool? reach = down is not null ? false : Any(f => f.ConnectionOk == true) ? true : null;
        var why = down?.ConnectionKind switch
        {
            "dns" => " Today the instance's name could not be found (DNS).",
            "tls" => " Today no secure connection (TLS) could be made -- a proxy that replaces certificates blocks it too.",
            "timeout" => " Today the instance did not answer in time.",
            "network" => " Today the instance could not be reached.",
            _ => "",
        };
        lines.Add(new("Network", "reachable", reach, "The instance is reachable over https from Azure, where SecurityInsight runs -- if your instance allows only listed IP addresses, add SecurityInsight's outbound address (your SecurityInsight admin has it)." + why));
        return lines;
    }

    /// The text the Copy button copies and the download holds: what is still to do first, then what is done. No secret, ever.
    public static string PlainText(ConnectorRow? c, IReadOnlyList<Line> lines, DateTime now, IReadOnlyList<TableDef>? tables = null)
    {
        var text = PlainTextLines(c, lines, now);
        if (tables is not { Count: > 0 }) return text;
        // #912: every table to create, with every column -- the team can build them from this text alone
        var sb = new StringBuilder(text);
        sb.Append("\nTABLES TO CREATE (each extends Import Set Row, sys_import_set_row; create every column with exactly this name)\n");
        foreach (var t in tables)
        {
            sb.Append("\n  ").Append(t.Title).Append(": ").Append(t.Table ?? "name not agreed yet").Append(" -- label: ").Append(t.Label).Append('\n');
            foreach (var col in t.Columns)
                sb.Append("    ").Append(col.Name).Append("  ").Append(col.Type).Append(col.Type == "string" ? " (" + col.MaxLength.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")" : "")
                  .Append(col.Label.Length > 0 && col.Label != col.Name ? "  (label: " + col.Label + ")" : "").Append(col.Meaning.Length > 0 ? " -- " + col.Meaning : "").Append('\n');
            sb.Append("    ").Append(t.Note).Append('\n');
        }
        var st = tables.FirstOrDefault(t => t.Key == "staging-status");
        if (st is not null)
        {
            sb.Append("\nHOW TO CREATE THE STAGING STATUS TABLE\n");
            var i = 1;
            foreach (var s in ServiceNowStagingStatus.Steps(st.Table)) sb.Append("  ").Append(i++.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(". ").Append(s).Append('\n');
        }
        return Scrub(c, sb.ToString());
    }

    private static string PlainTextLines(ConnectorRow? c, IReadOnlyList<Line> lines, DateTime now)
    {
        var sb = new StringBuilder();
        sb.Append("For your ServiceNow team -- what SecurityInsight's data out to ServiceNow still needs\n");
        sb.Append("Instance: ").Append(Instance(c) ?? "your ServiceNow instance").Append('\n');
        sb.Append("Written ").Append(now.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture)).Append(" UTC from the connector's newest checks. SecurityInsight sends rows to the staging tables through the Import Set API; your transform maps move them on.\n");
        void Part(string title, IEnumerable<Line> part)
        {
            var list = part.ToList();
            if (list.Count == 0) return;
            sb.Append('\n').Append(title).Append('\n');
            foreach (var g in list.GroupBy(l => l.Section))
            {
                sb.Append("  ").Append(g.Key).Append('\n');
                foreach (var l in g) sb.Append("    - ").Append(l.Text).Append('\n');
            }
        }
        Part("STILL TO DO", lines.Where(l => l.Done == false));
        Part("NOT KNOWN YET (check it, or SecurityInsight's next check tells)", lines.Where(l => l.Done is null));
        Part("DONE", lines.Where(l => l.Done == true));
        return Scrub(c, sb.ToString());
    }

    /// The download's file name.
    public static string FileName(string connector) => "servicenow-" + new string((connector ?? "").Where(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-').ToArray()) + "-for-your-servicenow-team.txt";

    /// Defence in depth: any Key Vault secret NAME the connector references is never in the text, whatever a line says.
    public static string Scrub(ConnectorRow? c, string text)
    {
        foreach (var p in Obj(c?.SecretRefsJson))
            if (p.Value is JsonValue v && v.TryGetValue<string>(out var name) && name.Trim().Length > 2)
                text = text.Replace(name.Trim(), "(a Key Vault secret)", StringComparison.OrdinalIgnoreCase);
        return text;
    }
}
