using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.ChangeJournal;

namespace SI.Management.Web.ConfigIo;

/// An uploaded file, kept for the person who uploaded it while they choose (30 minutes, in the web app's memory).
public sealed record UploadedConfig(string Token, string Owner, string FileName, string Content, JsonObject? Header, ConfigBackupFile.Verdict Verdict, string Message, DateTime UploadedUtc);

/// <summary>
/// The import's steps after the choice, through the product's NORMAL path -- nothing is written to the configuration here:
/// the file is kept as a configuration backup (cfg.ConfigBackupImport: audited, it can be restored from again later), and
/// the ticked items become PENDING CHANGES committed on Review &amp; commit through every gate -- or, with the second person
/// on (SIWeb_ConfigSecondPerson), a request another SuperAdmin decides on Backups (restore), exactly as a restore.
/// </summary>
public sealed class ConfigImportFlow(IConfigBackupStore backups, ConfigApplier applier, ConfigSettings settings, IConfigApprovalStore approvals, ChangeService changes, IMemoryCache cache)
{
    public static readonly TimeSpan KeepFor = TimeSpan.FromMinutes(30);
    private static string Key(string token) => "si-config-import-" + token;

    public UploadedConfig Keep(string owner, string fileName, string content, JsonObject? header, ConfigBackupFile.Verdict verdict, string message, DateTime nowUtc)
    {
        var u = new UploadedConfig(Guid.NewGuid().ToString("N"), owner, fileName, content, header, verdict, message, nowUtc);
        cache.Set(Key(u.Token), u, KeepFor);
        return u;
    }

    /// The upload of THIS person (another person's token reads as gone).
    public UploadedConfig? Find(string? token, string owner) =>
        !string.IsNullOrWhiteSpace(token) && cache.TryGetValue(Key(token), out UploadedConfig? u) && u is not null && u.Owner.Equals(owner, StringComparison.OrdinalIgnoreCase) ? u : null;

    public void Forget(string token) => cache.Remove(Key(token));

    public sealed record Outcome(int Staged, long BackupId, long? ApprovalId);

    /// Applies the chosen items: keeps the file as a backup, then stages each (or asks the second SuperAdmin).
    public async Task<Outcome> ApplyAsync(ClaimsPrincipal user, UploadedConfig u, IReadOnlyList<ConfigImport.Item> chosen, string reason, string? correlationId, string? version, CancellationToken ct)
    {
        if (chosen.Count > CacheStagingStore.MaxPerUser) throw new InvalidOperationException($"at most {CacheStagingStore.MaxPerUser} items can be pending at once -- import in parts (one section at a time)");
        var by = user.ChangeName();
        var note = $"imported from {u.FileName} on Export / Import ({u.Message})";
        var backupId = await backups.ImportAsync(u.Content, by, note.Length > 400 ? note[..400] : note, correlationId, version, ct);
        var items = new List<(ConfigDiff.Item Item, string? Expected)>();
        foreach (var c in chosen.Where(c => c.Diff is not null))
            items.Add((c.Diff!, (await applier.CurrentAsync(c.Diff!.Entity.Name, (c.Diff.Backup ?? c.Diff.Now)!, ct)).ContentSql));
        var s = await settings.ReadAsync(ct);
        if (s.SecondPerson)
        {
            var payload = new JsonObject
            {
                ["backupId"] = backupId,
                ["items"] = new JsonArray(items.Select(x => (JsonNode)new JsonObject
                {
                    ["entity"] = x.Item.Entity.Name, ["op"] = x.Item.RestoreOp, ["record"] = ((x.Item.RestoreOp == "Remove" ? x.Item.Now : x.Item.Backup)!).DeepClone(), ["expected"] = x.Expected,
                }).ToArray()),
            };
            var id = await approvals.RequestAsync(ConfigApproval.Restore, $"Import {items.Count} item(s) from {u.FileName} (backup #{backupId})", payload.ToJsonString(), reason, by, correlationId, ct);
            return new Outcome(0, backupId, id);
        }
        foreach (var x in items)
        {
            var rec = (x.Item.RestoreOp == "Remove" ? x.Item.Now : x.Item.Backup)!;
            await changes.StageAsync(user, ConfigRevertHandler.New(x.Item.Entity, x.Item.RestoreOp, rec, x.Expected, ConfigRevertHandler.SourceRestore, null, reason, by, null, backupId), ct);
        }
        return new Outcome(items.Count, backupId, null);
    }
}
