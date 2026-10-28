using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.ChangeJournal;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Configuration &gt; Backups (restore) (#404, framework CONFIG-1.3 / 1.4 / 1.5). The configuration backups: the daily job's
/// and "Back up now" (Admin), "no change" recorded without a copy, the retention (SI_Pro_ConfigBackupRetentionDays, default
/// 90 days; pruning is audited), pin / unpin (Admin), download as a signed file (Admin) and import one (SuperAdmin).
/// RESTORE -- pick what you restore (SuperAdmin): a backup against now per entity, record and field (added since /
/// removed since / changed since, settings old -> new); the ticked records (or whole entities) become PENDING CHANGES --
/// committed on Review &amp; commit through every gate, journaled with Source restore, undoable like any commit. With
/// SIWeb_ConfigSecondPerson on, the choice waits here for ANOTHER SuperAdmin, who approves it (the records are then staged
/// for the approver to commit: initiated by the requester, approved by the approver) or rejects it.
/// </summary>
public sealed class BackupsModel : PageModel
{
    private readonly IConfigBackupStore _backups;
    private readonly ConfigEntities _entities;
    private readonly ConfigApplier _applier;
    private readonly ConfigSettings _settings;
    private readonly IConfigApprovalStore _approvals;
    private readonly ChangeService _changes;
    private readonly IDataProtector _protector;
    private readonly ILogger<BackupsModel> _log;

    public BackupsModel(IConfigBackupStore backups, ConfigEntities entities, ConfigApplier applier, ConfigSettings settings, IConfigApprovalStore approvals,
        ChangeService changes, IDataProtectionProvider protection, ILogger<BackupsModel> log)
    {
        _backups = backups; _entities = entities; _applier = applier; _settings = settings; _approvals = approvals; _changes = changes;
        _protector = protection.CreateProtector(ConfigBackupFile.Purpose); _log = log;
    }

    public const int ReasonMin = 10;
    public const long MaxFileBytes = 20 * 1024 * 1024;

    [BindProperty(SupportsGet = true)] public long? Restore { get; set; }
    [BindProperty] public long BackupId { get; set; }
    [BindProperty] public bool Pinned { get; set; }
    [BindProperty] public string? Note { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public List<string> Pick { get; set; } = new();
    [BindProperty] public List<string> PickEntity { get; set; } = new();
    [BindProperty] public long ApprovalId { get; set; }
    [BindProperty] public bool Approve { get; set; }
    [BindProperty] public bool AcceptUnverified { get; set; }
    [BindProperty] public IFormFile? Upload { get; set; }

    public bool HasTable { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<ConfigBackup> Backups { get; private set; } = Array.Empty<ConfigBackup>();
    public ConfigSettings.Values Settings { get; private set; } = ConfigSettings.Values.Defaults;
    public IReadOnlyList<ConfigApproval> Approvals { get; private set; } = Array.Empty<ConfigApproval>();
    public ConfigBackup? Chosen { get; private set; }
    public IReadOnlyList<ConfigDiff.Item> Diff { get; private set; } = Array.Empty<ConfigDiff.Item>();
    public bool MayRestore => User.IsSuperAdmin();
    public ConfigEntities Entities => _entities;
    public string Me => User.ChangeName();

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            HasTable = await _backups.ExistsAsync(ct);
            Settings = await _settings.ReadAsync(ct);
            if (!HasTable) return;
            Backups = await _backups.ListAsync(500, ct);
            try { Approvals = await _approvals.RecentAsync(ConfigApproval.Restore, ct); } catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "restore approvals could not be read"); }
            if (Restore is { } id)
            {
                if (!MayRestore) { Error = "Only a SuperAdmin can restore from a backup."; return; }
                Chosen = Backups.FirstOrDefault(b => b.Id == id) ?? await _backups.FindAsync(id, ct);
                if (Chosen is null) { Error = "That backup does not exist (it may have been removed by the retention)."; return; }
                Diff = ConfigDiff.Compare(await _backups.ContentAsync(id, ct), await _backups.NowAsync(ct), _entities);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the configuration backups failed");
            Error = "The configuration backups could not be read: " + ex.Message;
        }
    }

    private IActionResult Back(string message, bool ok, long? restore = null)
    {
        TempData["toast"] = message; TempData["toastKind"] = ok ? "ok" : "error";
        return Redirect("/Admin/Backups" + (restore is { } r ? "?restore=" + r.ToString(CultureInfo.InvariantCulture) : ""));
    }

    private IActionResult Refused(string message, long? restore = null)
    {
        AuditScope.Current?.Refused(message);
        return Back("Not done: " + message, false, restore);
    }

    /// "Back up now" (Admin): the same backup as the daily job's; "no change" when nothing changed since the newest.
    [Audited("config.backup.take")]
    public async Task<IActionResult> OnPostBackupNowAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        try
        {
            if (!await _backups.ExistsAsync(ct)) return Refused("this database has no configuration backups yet (apply sql\\si-pro-settings.sql -- it only adds)");
            var note = string.IsNullOrWhiteSpace(Note) ? null : Note.Trim();
            var (id, noChange) = await _backups.TakeAsync(Me, "manual", note, AuditScope.Current?.CorrelationId, AppInfo.Version, ct);
            if (AuditScope.Current is { } a) { a.Target = "/Admin/Backups/backup/" + id.ToString(CultureInfo.InvariantCulture); a.Reason = note; a.AfterJson = JsonSerializer.Serialize(new { backupId = id, noChange, trigger = "manual" }); }
            return Back(noChange ? $"Backup #{id} recorded: nothing changed since the newest backup, so it points at that one instead of a second copy." : $"Backup #{id} taken.", true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "Back up now failed");
            AuditScope.Current?.Failed(ex.Message);
            return Back("The backup failed: " + ex.Message, false);
        }
    }

    /// Pin (kept past the retention) or unpin (Admin).
    [Audited("config.backup.pin")]
    public async Task<IActionResult> OnPostPinAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (AuditScope.Current is { } a) { a.Target = "/Admin/Backups/backup/" + BackupId.ToString(CultureInfo.InvariantCulture); a.Reason = Note; a.AfterJson = JsonSerializer.Serialize(new { pinned = Pinned }); }
        var changed = await _backups.PinAsync(BackupId, Pinned, Me, string.IsNullOrWhiteSpace(Note) ? null : Note.Trim(), ct);
        return changed ? Back(Pinned ? $"Backup #{BackupId} is pinned: the retention keeps it until it is unpinned." : $"Backup #{BackupId} is unpinned: the retention removes it once it is older than {Settings.BackupRetentionDays} days.", true)
                       : Refused("that backup was already " + (Pinned ? "pinned" : "unpinned") + " or does not exist");
    }

    /// Download a backup as a signed file (Admin). The file holds configuration only -- never a secret (a secret setting
    /// holds only its Key Vault secret's NAME).
    [Audited("config.backup.export")]
    public async Task<IActionResult> OnGetExportAsync(long id, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var b = await _backups.FindAsync(id, ct);
        if (b is null) return NotFound();
        var records = await _backups.ContentAsync(id, ct);
        var content = new JsonArray(records.Select(r => (JsonNode)new JsonObject { ["e"] = r.Entity, ["k"] = r.Key, ["r"] = r.Record.DeepClone() }).ToArray()).ToJsonString();
        var file = ConfigBackupFile.Build(b, content, Me, DateTime.UtcNow, _protector, AppInfo.Version);
        if (AuditScope.Current is { } a) { a.Target = "/Admin/Backups/backup/" + id.ToString(CultureInfo.InvariantCulture); a.Rows = records.Count; }
        var name = $"securityinsight-config-backup-{b.TakenUtc:yyyyMMdd-HHmm}-{id}.json";
        return File(Encoding.UTF8.GetBytes(file), "application/json", name);
    }

    /// Import a backup file as a backup (SuperAdmin). A file this installation signed is verified; one signed elsewhere (or
    /// unsigned) needs the explicit "I trust this file" tick; a file whose content does not match its checksum is refused.
    [Audited("config.backup.import")]
    public async Task<IActionResult> OnPostImportAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        if (Upload is null || Upload.Length == 0) return Refused("choose a backup file");
        if (Upload.Length > MaxFileBytes) return Refused($"the file is larger than {MaxFileBytes / 1024 / 1024} MB");
        string text;
        using (var r = new StreamReader(Upload.OpenReadStream(), Encoding.UTF8)) text = await r.ReadToEndAsync(ct);
        var (verdict, content, header, message) = ConfigBackupFile.Read(text, _protector);
        if (AuditScope.Current is { } a) { a.Target = "/Admin/Backups/file/" + Upload.FileName; a.AfterJson = JsonSerializer.Serialize(new { file = Upload.FileName, verdict = verdict.ToString(), message, from = ConfigEntities.Text(header?["takenUtc"]), exportedBy = ConfigEntities.Text(header?["exportedBy"]) }); }
        if (verdict == ConfigBackupFile.Verdict.Corrupt || content is null) return Refused(message);
        if (verdict != ConfigBackupFile.Verdict.Verified && !AcceptUnverified) return Refused(message + " -- tick \"I trust this file\" to import it anyway");
        var records = ConfigBackupFile.ParseContent(content);
        var unknown = records.Select(x => x.Entity).Distinct().Where(e => _entities.Find(e) is not { Backup: true }).ToList();
        if (unknown.Count > 0) return Refused("the file holds records this version does not know: " + string.Join(", ", unknown));
        var note = $"imported from {Upload.FileName} ({message})" + (string.IsNullOrWhiteSpace(Note) ? "" : ": " + Note.Trim());
        var id = await _backups.ImportAsync(content, Me, note.Length > 400 ? note[..400] : note, AuditScope.Current?.CorrelationId, ConfigEntities.Text(header?["productVersion"]), ct);
        return Back($"Imported as backup #{id} ({records.Count} record(s), {message}). Open it with Restore to pick what to restore.", true);
    }

    /// The records a restore writes back, from the ticks: single records, or whole entities.
    private IReadOnlyList<ConfigDiff.Item> Chosen_(IReadOnlyList<ConfigDiff.Item> diff) =>
        diff.Where(d => Pick.Contains(d.Id, StringComparer.Ordinal) || PickEntity.Contains(d.Entity.Name, StringComparer.Ordinal)).ToList();

    /// "Restore the ticked records" (SuperAdmin): staged for Review & commit -- or, with the second person on, sent to
    /// another SuperAdmin for approval. Nothing is written here.
    [Audited("config.restore.stage")]
    public async Task<IActionResult> OnPostRestoreAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        try
        {
            if (AuditScope.Current is { } a0) { a0.Target = "/Admin/Backups/backup/" + BackupId.ToString(CultureInfo.InvariantCulture); a0.Reason = Reason; }
            var why = (Reason ?? "").Trim();
            if (why.Length < ReasonMin) return Refused($"say why you restore (at least {ReasonMin} characters) -- it goes on the audit trail", BackupId);
            var b = await _backups.FindAsync(BackupId, ct);
            if (b is null) return Refused("that backup does not exist", null);
            var diff = ConfigDiff.Compare(await _backups.ContentAsync(BackupId, ct), await _backups.NowAsync(ct), _entities);
            var chosen = Chosen_(diff);
            if (chosen.Count == 0) return Refused("tick at least one record (or a whole area) to restore", BackupId);
            if (chosen.Count > CacheStagingStore.MaxPerUser) return Refused($"at most {CacheStagingStore.MaxPerUser} records can be pending at once -- restore in parts (one area at a time)", BackupId);
            // the live content each record must still have at commit time (else: changed since -- refused there)
            var items = new List<(ConfigDiff.Item Item, string? Expected)>();
            foreach (var d in chosen) items.Add((d, (await _applier.CurrentAsync(d.Entity.Name, (d.Backup ?? d.Now)!, ct)).ContentSql));
            var settings = await _settings.ReadAsync(ct);
            if (AuditScope.Current is { } a) a.AfterJson = JsonSerializer.Serialize(new { backupId = BackupId, records = chosen.Count, secondPerson = settings.SecondPerson, areas = chosen.GroupBy(c => c.Entity.Label).Select(g => new { area = g.Key, n = g.Count() }) });
            if (settings.SecondPerson)
            {
                var payload = new JsonObject
                {
                    ["backupId"] = BackupId,
                    ["items"] = new JsonArray(items.Select(x => (JsonNode)new JsonObject
                    {
                        ["entity"] = x.Item.Entity.Name, ["op"] = x.Item.RestoreOp, ["record"] = ((x.Item.RestoreOp == "Remove" ? x.Item.Now : x.Item.Backup)!).DeepClone(), ["expected"] = x.Expected,
                    }).ToArray()),
                };
                var title = $"Restore {chosen.Count} record(s) from backup #{BackupId} ({b.TakenUtc:yyyy-MM-dd HH:mm} UTC)";
                var id = await _approvals.RequestAsync(ConfigApproval.Restore, title, payload.ToJsonString(), why, Me, AuditScope.Current?.CorrelationId, ct);
                return Back($"Sent for approval (request #{id}): another SuperAdmin approves or rejects it on this page. Nothing has changed yet.", true);
            }
            foreach (var x in items)
            {
                var rec = (x.Item.RestoreOp == "Remove" ? x.Item.Now : x.Item.Backup)!;
                await _changes.StageAsync(User, ConfigRevertHandler.New(x.Item.Entity, x.Item.RestoreOp, rec, x.Expected, ConfigRevertHandler.SourceRestore, null, why, Me, null, BackupId), ct);
            }
            TempData["toast"] = $"{items.Count} record(s) from backup #{BackupId} staged -- review them on Review & commit and commit there. Nothing has changed yet.";
            TempData["toastKind"] = "ok";
            return Redirect("/Changes");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException)
        {
            return Refused(ex.Message, BackupId);
        }
    }

    /// A second SuperAdmin approves (the records are staged for THEM to commit) or rejects a restore someone else asked for.
    [Audited("config.approval.decide")]
    public async Task<IActionResult> OnPostDecideAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        var req = await _approvals.FindAsync(ApprovalId, ct);
        if (AuditScope.Current is { } a) { a.Target = "/Admin/Backups/approval/" + ApprovalId.ToString(CultureInfo.InvariantCulture); a.Reason = Note; a.AfterJson = JsonSerializer.Serialize(new { approve = Approve, kind = req?.Kind, requestedBy = req?.RequestedBy }); }
        if (req is null || req.Kind != ConfigApproval.Restore) return Refused("that request does not exist");
        if (!req.MayDecide(Me, DateTime.UtcNow)) return Refused(string.Equals(req.RequestedBy, Me, StringComparison.OrdinalIgnoreCase) ? "you asked for it -- another SuperAdmin decides" : "it is no longer waiting (decided or expired)");
        if (!await _approvals.DecideAsync(req.Id, Approve, Me, string.IsNullOrWhiteSpace(Note) ? null : Note.Trim(), ct)) return Refused("it was decided or expired in the meantime");
        if (!Approve) { await _approvals.SetOutcomeAsync(req.Id, "rejected", "rejected by " + Me, ct); return Back($"Rejected: request #{req.Id} of {req.RequestedBy}. Nothing was restored.", true); }
        var payload = JsonNode.Parse(req.PayloadJson) as JsonObject;
        var backupId = payload?["backupId"]?.GetValue<long>();
        var staged = 0;
        foreach (var it in (payload?["items"] as JsonArray ?? new JsonArray()).OfType<JsonObject>())
        {
            var e = _entities.Find(ConfigEntities.Text(it["entity"]));
            if (e is null || it["record"] is not JsonObject rec) continue;
            var expected = it["expected"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
            await _changes.StageAsync(User, ConfigRevertHandler.New(e, ConfigEntities.Text(it["op"]), (JsonObject)rec.DeepClone(), expected, ConfigRevertHandler.SourceRestore, null,
                req.Reason ?? req.Title, req.RequestedBy, req.Id, backupId), ct);
            staged++;
        }
        await _approvals.SetOutcomeAsync(req.Id, "approved", $"approved by {Me}; {staged} record(s) staged for {Me} to commit", ct);
        TempData["toast"] = $"Approved: {staged} record(s) of {req.RequestedBy}'s restore are staged for you -- commit them on Review & commit (you are recorded as the approver).";
        TempData["toastKind"] = "ok";
        return Redirect("/Changes");
    }
}
