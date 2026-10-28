using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.ChangeJournal;

/// <summary>
/// #404 (framework CONFIG-1.2 / 1.4) -- an undo or a restore is a PENDING CHANGE like any other: one staged change per
/// record (kind config-revert), reviewed on Review &amp; commit (before -> after, refused when the record changed since it was
/// staged) and committed through the ONE commit path -- every gate, the role check on review and on commit, one commit id
/// for the whole commit -- by <see cref="ConfigApplier"/>, journaled with Source = undo (UndoOf = the commit it reverses) or
/// Source = restore. Never a direct table write: an undo is itself undoable.
/// Who: an undo -- a SuperAdmin any commit, an Admin only their own; a restore -- a SuperAdmin only; a record whose
/// entity only a SuperAdmin may change (access) -- a SuperAdmin. A restore a second SuperAdmin approved (CONFIG-1.5) is
/// committed by that approver: initiated by the requester, approved by the committer.
/// </summary>
public sealed class ConfigRevertHandler : IStagedChangeHandler
{
    private readonly ConfigApplier _applier;
    private readonly ConfigEntities _entities;
    private readonly IConfigApprovalStore? _approvals;
    public ConfigRevertHandler(ConfigApplier applier, ConfigEntities entities, IConfigApprovalStore? approvals = null) { _applier = applier; _entities = entities; _approvals = approvals; }

    public bool Handles(string kind) => kind == ChangeKinds.ConfigRevert;

    public const string SourceUndo = "undo";
    public const string SourceRestore = "restore";

    /// A staged change for one record. Nothing is written.
    public static StagedChange New(ConfigEntities.Entity e, string op, JsonObject record, string? expectedContent, string source, string? undoOf, string reason,
        string? initiator = null, long? approvalId = null, long? backupId = null)
    {
        var key = ConfigEntities.KeyOf(e, record);
        var verb = source == SourceUndo ? "Undo" : "Restore";
        var what = op switch { "Add" => "put back", "Remove" => "take out", _ => "set back" };
        var c = new StagedChange
        {
            Kind = ChangeKinds.ConfigRevert,
            Title = $"{verb}: {e.Label} {key} -- {what}",
        };
        c.Data["entity"] = e.Name; c.Data["key"] = key; c.Data["op"] = op; c.Data["record"] = record.ToJsonString();
        c.Data["expected"] = expectedContent; c.Data["expectedNone"] = expectedContent is null ? "1" : "0";
        c.Data["source"] = source; c.Data["undoOf"] = undoOf; c.Data["reason"] = reason; c.Data["initiator"] = initiator;
        c.Data["approvalId"] = approvalId?.ToString(CultureInfo.InvariantCulture); c.Data["backupId"] = backupId?.ToString(CultureInfo.InvariantCulture);
        return c;
    }

    /// The role check of a config-revert change (ChangeAccess calls it on stage, review and commit).
    public static AccessDecision Access(ClaimsPrincipal user, StagedChange c, ConfigEntities entities)
    {
        if (!user.IsAdmin()) return AccessDecision.No("only an Admin can undo, and only a SuperAdmin can restore");
        var e = entities.Find(c.Get("entity"));
        if (e is null) return AccessDecision.No("this kind of record is not part of the configuration set");
        if (string.Equals(e.MinRole, "SuperAdmin", StringComparison.Ordinal) && !user.IsSuperAdmin()) return AccessDecision.No($"only a SuperAdmin can change {e.Label}");
        if (c.Get("source") == SourceRestore && !user.IsSuperAdmin()) return AccessDecision.No("only a SuperAdmin can restore from a backup");
        if (c.Get("source") == SourceUndo && !user.IsSuperAdmin() && !string.Equals(c.Get("initiator"), user.ChangeName(), StringComparison.OrdinalIgnoreCase))
            return AccessDecision.No("an Admin can undo only their own commits -- a SuperAdmin can undo any");
        return AccessDecision.Yes;
    }

    private ConfigWrite? WriteOf(StagedChange c, out ConfigEntities.Entity? e)
    {
        e = _entities.Find(c.Get("entity"));
        var rec = ConfigEntities.Parse(c.Get("record"));
        if (e is null || rec is null) return null;
        var expected = c.Get("expectedNone") == "1" ? null : c.Get("expected");
        return new ConfigWrite(e.Name, c.Get("op") ?? "", rec, expected, c.Get("source") ?? SourceUndo, c.Get("undoOf"), c.Get("reason") ?? c.Title);
    }

    /// PURE. A record's content as lines a person reads ("Field: value").
    public static string Describe(ConfigEntities.Entity e, JsonObject? record)
    {
        if (record is null) return "(not in force)";
        var sb = new StringBuilder();
        foreach (var col in e.Content) sb.Append(col).Append(": ").Append(ConfigEntities.Show(record[col])).Append('\n');
        return sb.ToString().TrimEnd();
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange change, CancellationToken ct)
    {
        var w = WriteOf(change, out var e);
        if (w is null || e is null) return new ChangePreview(change, "", "", new[] { "this change cannot be read any more -- discard it" }, Array.Empty<string>());
        var problems = new List<string>(); var warnings = new List<string>();
        if (!e.Undo) problems.Add($"{e.Label} cannot be undone or restored: {e.NoUndoWhy}");
        var cur = await _applier.CurrentAsync(e.Name, w.Record, ct);
        if (!string.Equals(cur.ContentSql, w.ExpectedContent, StringComparison.Ordinal))
            problems.Add("this record changed since the change was staged -- discard it and stage it again from the commit history or the backup");
        if (change.Get("approvalId") is { Length: > 0 }) warnings.Add("Approved by you as the second SuperAdmin: committing it records the requester as the one who initiated it and you as the approver.");
        var after = w.Op == "Remove" ? "(taken out of force)" : Describe(e, w.Record);
        return new ChangePreview(change, Describe(e, cur.Record), after, problems, warnings);
    }

    public async Task<WriteResult> CommitAsync(StagedChange change, string by, CancellationToken ct)
    {
        var w = WriteOf(change, out var e);
        if (w is null || e is null) return new WriteResult(WriteStatus.Refused, "this change cannot be read any more -- discard it");
        string? initiatedBy = null, approvedBy = null;
        if (long.TryParse(change.Get("approvalId"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var approvalId) && approvalId > 0)
        {
            // CONFIG-1.5: the approval must be approved, by the committer, and not by the requester
            var a = _approvals is null ? null : await _approvals.FindAsync(approvalId, ct);
            if (a is null || a.State != "approved" || !string.Equals(a.DecidedBy, by, StringComparison.OrdinalIgnoreCase) || string.Equals(a.RequestedBy, by, StringComparison.OrdinalIgnoreCase))
                return new WriteResult(WriteStatus.Refused, "this restore needs a second SuperAdmin's approval, and only the approver commits it");
            initiatedBy = a.RequestedBy; approvedBy = by;
        }
        var scope = AuditScope.Current;
        if (scope is not null && scope.Action.StartsWith("changes.", StringComparison.Ordinal))
            scope.Action = w.Source == SourceRestore ? "config.backup.restore" : "config.commit.undo";
        using (scope?.Journal(w.Source, w.UndoOf, initiatedBy, approvedBy, w.Reason))
            return await _applier.ApplyAsync(w, by, ct);
    }
}
