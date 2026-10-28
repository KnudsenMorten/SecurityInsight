using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.ChangeJournal;

/// The live record of one configuration key: its full record and its content exactly as the database writes it (the
/// optimistic check of an undo / restore compares that text byte for byte at commit).
public sealed record ConfigCurrent(JsonObject? Record, string? ContentSql);

/// One record written back by an undo or a restore: Add (put the record in force), Modify (set its content), Remove (take
/// it out of force: a soft removal where the entity has one, else a delete). <paramref name="Record"/> is the target for
/// Add / Modify and the record being removed for Remove; <paramref name="ExpectedContent"/> is the live content the person
/// was shown (null = no live record) -- anything else at commit is "changed since", and nothing is written.
public sealed record ConfigWrite(string Entity, string Op, JsonObject Record, string? ExpectedContent, string Source, string? UndoOf, string Reason);

/// <summary>
/// #404 (framework CONFIG-1.2 / 1.4) -- THE ONE GENERIC WRITER of an undo or a restore. A record goes back through ONE
/// transaction that (1) locks and re-reads the live record and refuses when it is not what the person was shown,
/// (2) writes the record with the entity's own rules -- its key, its soft removal (a removal sets RevokedAt / RetiredAt /
/// RemovedAt / UnlinkedAt, never deletes such a row), its stamps (UpdatedAt / UpdatedBy are now and the person), an
/// IDENTITY column never written -- and (3) adds its cfg.ChangeLog row (Kind undo / restore) for the per-setting history.
/// The table's journal trigger records the change in the same transaction, with the request's commit id, Source = undo /
/// restore and UndoOf (the audit scope carries them into SESSION_CONTEXT). Column names come only from the configuration
/// set (plain names, checked when it loads); every value is a parameter.
/// </summary>
public sealed class ConfigApplier
{
    private readonly ISqlExecutor _sql;
    private readonly ConfigEntities _entities;
    public ConfigApplier(ISqlExecutor sql, ConfigEntities entities) { _sql = sql; _entities = entities; }

    private static string Q(string c) => "[" + c + "]";

    /// The record's content as JSON, columns in catalog order -- the trigger's expression (byte-identical output).
    public static string ContentExpr(ConfigEntities.Entity e, string alias) =>
        "(SELECT " + string.Join(", ", e.Content.Select(c => $"{alias}.{Q(c)} AS {Q(c)}")) + " FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES)";

    public static string RecordExpr(ConfigEntities.Entity e, string alias) =>
        "(SELECT " + string.Join(", ", e.Columns.Select(c => $"{alias}.{Q(c)} AS {Q(c)}")) + " FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES)";

    /// "t.[A] = @k0 AND (t.[B] = @k1 OR (t.[B] IS NULL AND @k1 IS NULL))": the key match, NULL-safe.
    public static string KeyWhere(ConfigEntities.Entity e, string alias) =>
        string.Join(" AND ", e.Key.Select((k, i) => $"({alias}.{Q(k)} = @k{i} OR ({alias}.{Q(k)} IS NULL AND @k{i} IS NULL))"));

    public static string LiveWhere(ConfigEntities.Entity e, string alias) => e.SoftRemove is { } s ? $" AND {alias}.{Q(s.At)} IS NULL" : "";

    /// A JSON value as a SQL parameter: text as text, true/false as 1/0, a number as written, null as NULL.
    public static object? Param(JsonNode? n) => n switch
    {
        null => null,
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        JsonValue v when v.TryGetValue<bool>(out var b) => b ? 1 : 0,
        JsonValue v when v.TryGetValue<long>(out var l) => l,
        JsonValue v when v.TryGetValue<decimal>(out var d) => d,
        _ => n.ToJsonString(),
    };

    private static Dictionary<string, object?> KeyParams(ConfigEntities.Entity e, JsonObject record)
    {
        var p = new Dictionary<string, object?>();
        for (var i = 0; i < e.Key.Count; i++) p["k" + i.ToString(CultureInfo.InvariantCulture)] = Param(record[e.Key[i]]);
        return p;
    }

    public static string CurrentSql(ConfigEntities.Entity e) =>
        $"SELECT TOP (1) {RecordExpr(e, "t")} AS RecordJson, {ContentExpr(e, "t")} AS ContentJson FROM {e.Table} AS t WHERE {KeyWhere(e, "t")}{LiveWhere(e, "t")};";

    /// The live record of a key (a record carrying the key columns), or none.
    public async Task<ConfigCurrent> CurrentAsync(string entity, JsonObject keyRecord, CancellationToken ct)
    {
        var e = _entities.Find(entity) ?? throw new ArgumentException($"'{entity}' is not a configuration entity");
        var row = (await _sql.QueryAsync(CurrentSql(e), KeyParams(e, keyRecord), ct)).FirstOrDefault();
        return row is null ? new ConfigCurrent(null, null) : new ConfigCurrent(ConfigEntities.Parse(row.Str("RecordJson")), row.Str("ContentJson"));
    }

    /// PURE. The batch that writes one record (see the class summary); its parameters are built by <see cref="ParamsFor"/>.
    public static string WriteSql(ConfigEntities.Entity e, string op)
    {
        var sb = new StringBuilder();
        var cur = $"(SELECT TOP (1) {ContentExpr(e, "t")} FROM {e.Table} AS t WITH (UPDLOCK, HOLDLOCK) WHERE {KeyWhere(e, "t")}{LiveWhere(e, "t")})";
        sb.Append("SET XACT_ABORT ON;\nBEGIN TRAN;\n");
        sb.Append($"DECLARE @cur NVARCHAR(MAX) = {cur};\n");
        sb.Append("IF ISNULL(@cur, N'') COLLATE Latin1_General_BIN2 <> ISNULL(@Expected, N'') COLLATE Latin1_General_BIN2\n");
        sb.Append("BEGIN ROLLBACK; SELECT N'Stale' AS Outcome, @cur AS Cur; RETURN; END\n");
        var writable = e.Columns.Where(c => !string.Equals(c, e.Identity, StringComparison.Ordinal)).ToList();
        string ValueOf(string c) => c == e.UpdatedAt ? "SYSUTCDATETIME()" : c == e.UpdatedBy ? "@Actor" : "@c_" + c;
        switch (op)
        {
            case "Remove":
                if (e.SoftRemove is { } s)
                    sb.Append($"UPDATE t SET t.{Q(s.At)} = SYSUTCDATETIME(){(s.By is { } by ? $", t.{Q(by)} = @Actor" : "")}{(e.UpdatedAt is { } ua ? $", t.{Q(ua)} = SYSUTCDATETIME()" : "")}{(e.UpdatedBy is { } ub ? $", t.{Q(ub)} = @Actor" : "")} FROM {e.Table} AS t WHERE {KeyWhere(e, "t")}{LiveWhere(e, "t")};\n");
                else
                    sb.Append($"DELETE t FROM {e.Table} AS t WHERE {KeyWhere(e, "t")};\n");
                break;
            case "Modify":
            {
                var set = writable.Where(c => !e.Pk.Contains(c, StringComparer.Ordinal) && (!e.Meta.Contains(c, StringComparer.Ordinal) || c == e.UpdatedAt || c == e.UpdatedBy))
                                  .Select(c => $"t.{Q(c)} = {ValueOf(c)}");
                sb.Append($"UPDATE t SET {string.Join(", ", set)} FROM {e.Table} AS t WHERE {KeyWhere(e, "t")}{LiveWhere(e, "t")};\n");
                break;
            }
            case "Add":
            {
                // a removed row with the record's primary key is put back in force (its history stays); else a new row
                var pkWhere = string.Join(" AND ", e.Pk.Select(c => $"t.{Q(c)} = @c_{c}"));
                var set = writable.Where(c => !e.Pk.Contains(c, StringComparer.Ordinal)).Select(c => $"t.{Q(c)} = {ValueOf(c)}");
                sb.Append($"IF EXISTS (SELECT 1 FROM {e.Table} AS t WHERE {pkWhere})\n");
                sb.Append($"    UPDATE t SET {string.Join(", ", set)} FROM {e.Table} AS t WHERE {pkWhere};\n");
                sb.Append($"ELSE\n    INSERT {e.Table} ({string.Join(", ", writable.Select(Q))}) VALUES ({string.Join(", ", writable.Select(ValueOf))});\n");
                break;
            }
            default: throw new ArgumentException($"'{op}' is not Add, Modify or Remove");
        }
        sb.Append("IF @@ROWCOUNT <> 1 THROW 51420, N'the record could not be written back (it was not found as expected) -- nothing was changed', 1;\n");
        var after = $"(SELECT TOP (1) {ContentExpr(e, "t")} FROM {e.Table} AS t WHERE {KeyWhere(e, "t")}{LiveWhere(e, "t")})";
        sb.Append("INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)\n");
        sb.Append($"VALUES (@LogName, @LogScope, @LogKind, @LogAction, @cur, {after}, @Actor, @Reason);\n");
        sb.Append("COMMIT;\nSELECT N'Saved' AS Outcome;");
        return sb.ToString();
    }

    /// PURE. The parameters of <see cref="WriteSql"/>.
    public static Dictionary<string, object?> ParamsFor(ConfigEntities.Entity e, ConfigWrite w, string actor)
    {
        var p = KeyParams(e, w.Record);
        foreach (var c in e.Columns) p["c_" + c] = Param(w.Record[c]);
        p["Expected"] = w.ExpectedContent;
        p["Actor"] = actor;
        p["Reason"] = w.Reason.Length > 400 ? w.Reason[..400] : w.Reason;
        var setting = e.Name == "setting";
        var name = setting ? ConfigEntities.Text(w.Record["Name"]) : e.Name + "/" + ConfigEntities.KeyOf(e, w.Record);
        p["LogName"] = name.Length > 128 ? name[..128] : name;
        p["LogScope"] = setting ? ConfigEntities.Text(w.Record["Scope"]) : e.ChangeLogScope;
        p["LogKind"] = w.Source;
        p["LogAction"] = w.Op == "Remove" ? "Reset" : "Set";
        return p;
    }

    /// Writes one record back. Saved, or Stale ("changed since"), or Refused with the database's reason.
    public async Task<WriteResult> ApplyAsync(ConfigWrite w, string actor, CancellationToken ct)
    {
        var e = _entities.Find(w.Entity);
        if (e is null) return new WriteResult(WriteStatus.Refused, $"'{w.Entity}' is not a configuration entity");
        if (!e.Undo) return new WriteResult(WriteStatus.Refused, $"{e.Label} cannot be undone or restored: {e.NoUndoWhy}");
        if (w.Op is not ("Add" or "Modify" or "Remove")) return new WriteResult(WriteStatus.Refused, $"'{w.Op}' is not Add, Modify or Remove");
        // the pipeline's mode also switches the jobs' timers: it is changed on the Jobs page, never written back here
        if (e.Name == "jobflow" && w.Op != "Remove" && w.ExpectedContent is { } ex && ConfigEntities.Parse(ex) is { } now
            && ConfigEntities.Text(now["Mode"]) != ConfigEntities.Text(w.Record["Mode"]))
            return new WriteResult(WriteStatus.Refused, "the pipeline's mode (pipeline or own schedules) also switches the jobs' timers -- switch it on " + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/Jobs") + "; the definition itself can be restored once the mode matches");
        var rows = await _sql.QueryAsync(WriteSql(e, w.Op), ParamsFor(e, w, actor), ct);
        var outcome = rows.FirstOrDefault()?.Str("Outcome");
        return outcome switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, $"{e.Label}: {ConfigEntities.KeyOf(e, w.Record)} {(w.Op == "Add" ? "put back" : w.Op == "Remove" ? "taken out" : "set back")}"),
            "Stale" => new WriteResult(WriteStatus.Stale, $"{e.Label}: {ConfigEntities.KeyOf(e, w.Record)} changed since you looked -- review it again"),
            _ => new WriteResult(WriteStatus.Refused, "the write returned no outcome"),
        };
    }
}
