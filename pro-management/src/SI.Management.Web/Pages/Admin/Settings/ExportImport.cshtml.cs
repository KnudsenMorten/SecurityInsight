using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.ChangeJournal;
using SI.Management.Web.ConfigIo;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// Export / Import (framework CONFIG-IO-1, SI #490) -- SuperAdmin. EXPORT: all of the configuration or chosen sections to
/// ONE signed, versioned JSON file (the backup format with the CONFIG-IO-1 header; never a secret value). IMPORT, select
/// which: upload a file -> its checks (signature, newer = refused, unknown sections = refused, another tenant = object ids
/// flagged) -> a per-section and per-item comparison (new / changed / unchanged / only here) -> tick -> Preview (nothing is
/// written) -> Apply: the file is kept as a backup and the ticked items become pending changes committed on Review &amp;
/// commit through every gate (or a second SuperAdmin's approval, as a restore). Every step on the audit trail.
/// </summary>
[Authorize(Policy = Policies.SuperAdmin)]
public sealed class ExportImportModel(IConfigBackupStore backups, ConfigEntities entities, ConfigImportFlow flow, HeaderContext header, IDataProtectionProvider protection,
    TimeProvider clock, ILogger<ExportImportModel> log) : PageModel
{
    private readonly IDataProtector _protector = protection.CreateProtector(ConfigBackupFile.Purpose);
    public const int ReasonMin = 10;

    [BindProperty(SupportsGet = true)] public string? T { get; set; }
    [BindProperty(SupportsGet = true)] public List<string> S { get; set; } = new();
    [BindProperty] public List<string> Pick { get; set; } = new();
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public bool AcceptUnverified { get; set; }
    [BindProperty] public IFormFile? Upload { get; set; }

    public bool HasTable { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<ConfigEntities.Entity> Sections => ConfigExport.Sections(entities);
    public IReadOnlyDictionary<string, int> Counts { get; private set; } = new Dictionary<string, int>();
    public UploadedConfig? Uploaded { get; private set; }
    public ConfigImport.Plan? Plan { get; private set; }
    public IReadOnlyList<ConfigImport.Item>? Preview { get; private set; }

    private async Task<(string? TenantId, string? Environment)> InstallAsync(CancellationToken ct)
    {
        try { var h = await header.ReadAsync(ct); return (h.TenantId, h.EnvironmentName); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "export / import: header facts"); return (null, null); }
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        HasTable = await backups.ExistsAsync(ct);
        if (!HasTable) return;
        Counts = (await backups.NowAsync(ct)).GroupBy(r => r.Entity).ToDictionary(g => g.Key, g => g.Count());
        Uploaded = flow.Find(T, User.ChangeName());
        if (T is not null && Uploaded is null) Error = "That upload is gone (it is kept 30 minutes, for the person who uploaded it) -- upload the file again.";
        if (Uploaded is not null)
        {
            var (tenant, _) = await InstallAsync(ct);
            Plan = ConfigImport.Build(Uploaded.Header, ConfigBackupFile.ParseContent(Uploaded.Content), await backups.NowAsync(ct), entities, S, AppInfo.Version, tenant);
        }
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { await LoadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogError(ex, "export / import"); Error = "The configuration could not be read: " + ex.Message; }
    }

    private IActionResult Back(string message, bool ok, string? token = null)
    {
        TempData["toast"] = message; TempData["toastKind"] = ok ? "ok" : "error";
        return Redirect("/Admin/Settings/ExportImport" + (token is null ? "" : "?t=" + token));
    }

    private IActionResult Refused(string message, string? token = null)
    {
        AuditScope.Current?.Refused(message);
        return Back("Not done: " + message, false, token);
    }

    /// EXPORT: the chosen sections (none chosen = all) as one signed file.
    [Audited("config.io.export")]
    public async Task<IActionResult> OnGetExportAsync(CancellationToken ct)
    {
        if (!await backups.ExistsAsync(ct)) return Refused("this database has no configuration set yet (apply sql\\si-pro-settings.sql -- it only adds)");
        var unknown = S.Where(s => entities.Find(s) is not { Backup: true }).ToList();
        if (unknown.Count > 0) return Refused("unknown section(s): " + string.Join(", ", unknown));
        var records = ConfigExport.Pick(await backups.NowAsync(ct), S);
        var (tenant, env) = await InstallAsync(ct);
        var now = clock.GetUtcNow().UtcDateTime;
        var file = ConfigExport.Build(records, S, new ConfigExport.Header(AppInfo.Version, tenant, env, now, User.ChangeName()), _protector);
        if (AuditScope.Current is { } a) { a.Target = "/Admin/Settings/ExportImport/export"; a.Rows = records.Count; a.AfterJson = JsonSerializer.Serialize(new { sections = S.Count == 0 ? new List<string> { "(all)" } : S, records = records.Count }); }
        return File(Encoding.UTF8.GetBytes(file), "application/json", $"securityinsight-config-{now:yyyyMMdd-HHmm}.json");
    }

    /// IMPORT step 1: upload and check the file; it is kept for 30 minutes while the person chooses. Nothing is written.
    [Audited("config.io.inspect")]
    public async Task<IActionResult> OnPostInspectAsync(CancellationToken ct)
    {
        if (Upload is null || Upload.Length == 0) return Refused("choose a configuration file");
        if (Upload.Length > ChangeJournalLimits.MaxFileBytes) return Refused($"the file is larger than {ChangeJournalLimits.MaxFileBytes / 1024 / 1024} MB");
        string text;
        using (var r = new StreamReader(Upload.OpenReadStream(), Encoding.UTF8)) text = await r.ReadToEndAsync(ct);
        var (verdict, content, hdr, message) = ConfigBackupFile.Read(text, _protector);
        if (AuditScope.Current is { } a) { a.Target = "/Admin/Settings/ExportImport/file/" + Upload.FileName; a.AfterJson = JsonSerializer.Serialize(new { file = Upload.FileName, verdict = verdict.ToString(), message, from = ConfigEntities.Text(hdr?["tenantId"]), version = ConfigEntities.Text(hdr?["productVersion"]), exportedBy = ConfigEntities.Text(hdr?["exportedBy"]) }); }
        if (verdict == ConfigBackupFile.Verdict.Corrupt || content is null) return Refused(message);
        var u = flow.Keep(User.ChangeName(), Upload.FileName, content, hdr, verdict, message, clock.GetUtcNow().UtcDateTime);
        return Back($"{Upload.FileName}: {message}. Choose what to import below.", true, u.Token);
    }

    private (IReadOnlyList<ConfigImport.Item>? Chosen, IActionResult? Refusal) Choose()
    {
        if (Uploaded is null) return (null, Refused("that upload is gone -- upload the file again"));
        if (Plan is null || Plan.Refused) return (null, Refused("the file cannot be imported: " + string.Join("; ", Plan?.Refusals ?? Array.Empty<string>()), T));
        if (Uploaded.Verdict != ConfigBackupFile.Verdict.Verified && !AcceptUnverified) return (null, Refused(Uploaded.Message + " -- tick \"I trust this file\" to import from it", T));
        var chosen = Plan.Items.Where(i => i.State != ConfigImport.State.Unchanged && Pick.Contains(i.Id, StringComparer.Ordinal)).ToList();
        if (chosen.Count == 0) return (null, Refused("tick at least one item to import", T));
        return (chosen, null);
    }

    /// PREVIEW (-WhatIf): what Apply would stage, shown on the page. Nothing is written.
    [Audited("config.io.preview")]
    public async Task<IActionResult> OnPostPreviewAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        var (chosen, refusal) = Choose();
        if (refusal is not null) return refusal;
        Preview = chosen;
        return Page();
    }

    /// APPLY: the file kept as a backup; the ticked items staged for Review & commit (or sent to a second SuperAdmin).
    [Audited("config.io.stage")]
    public async Task<IActionResult> OnPostApplyAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        if (AuditScope.Current is { } a0) { a0.Target = "/Admin/Settings/ExportImport/file/" + Uploaded?.FileName; a0.Reason = Reason; }
        var why = (Reason ?? "").Trim();
        if (why.Length < ReasonMin) return Refused($"say why you import (at least {ReasonMin} characters) -- it goes on the audit trail", T);
        var (chosen, refusal) = Choose();
        if (refusal is not null) return refusal;
        try
        {
            var o = await flow.ApplyAsync(User, Uploaded!, chosen!, why, AuditScope.Current?.CorrelationId, ConfigEntities.Text(Uploaded!.Header?["productVersion"]), ct);
            if (AuditScope.Current is { } a) a.AfterJson = JsonSerializer.Serialize(new { file = Uploaded.FileName, backupId = o.BackupId, staged = o.Staged, approvalId = o.ApprovalId, sections = chosen!.GroupBy(c => c.Entity.Label).Select(g => new { section = g.Key, n = g.Count() }), flagged = chosen!.Count(c => c.Flag is not null) });
            flow.Forget(Uploaded.Token);
            if (o.ApprovalId is { } id) return Back($"Sent for approval (request #{id}): another SuperAdmin approves or rejects it on Backups (restore). The file is kept as backup #{o.BackupId}. Nothing has changed yet.", true);
            TempData["toast"] = $"{o.Staged} item(s) from {Uploaded.FileName} staged -- review and commit them on Review & commit. The file is kept as backup #{o.BackupId}. Nothing has changed yet.";
            TempData["toastKind"] = "ok";
            return Redirect("/Changes");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException)
        {
            return Refused(ex.Message, T);
        }
    }
}

/// The upload limit the backups page uses (one number for both uploads).
public static class ChangeJournalLimits
{
    public const long MaxFileBytes = BackupsModel.MaxFileBytes;
}
