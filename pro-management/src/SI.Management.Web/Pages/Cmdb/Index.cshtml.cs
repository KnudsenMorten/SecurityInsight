using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Cmdb;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Cmdb;

/// <summary>
/// The CMDB page (#256): the business services of the AUTHORITATIVE CMDB and where they come from. SecurityInsight's own
/// CMDB: add, edit (on the service's page) and retire services -- never remove, the history stays. An external CMDB:
/// read-only here; a CSV is uploaded (validated, with a row-level error report) and a ServiceNow CMDB arrives through
/// the scheduled connector import. A v2.2 CMDB.csv is imported ONCE into SecurityInsight's own CMDB (migration).
/// Readers see everything; every change needs Admin, checked here and again by the store inside its transaction.
/// </summary>
[RequestSizeLimit(12 * 1024 * 1024)]
public sealed class IndexModel : SI.Management.Web.Columns.DataViewPageModel
{
    private readonly ICmdbStore _store;
    private readonly ICmdbSqlSyncReader _ciTable;
    private readonly ILogger<IndexModel> _log;
    public IndexModel(ICmdbStore store, ICmdbSqlSyncReader ciTable, ILogger<IndexModel> log) { _store = store; _ciTable = ciTable; _log = log; }

    /// The SQL CMDB connector's CI table (#271): read only, shown in its own small card; a failure there never hides the CMDB.
    public CmdbSqlSyncState CiTable { get; private set; } = CmdbSqlSyncState.Missing;
    public string? CiTableError { get; private set; }

    [BindProperty(SupportsGet = true)] public bool Retired { get; set; }

    public CmdbSchema Schema { get; private set; } = new(false, false);
    public string Source { get; private set; } = CmdbSources.SI;
    public IReadOnlyList<CmdbService> Services { get; private set; } = Array.Empty<CmdbService>();
    public IReadOnlyList<CmdbImportRow> Imports { get; private set; } = Array.Empty<CmdbImportRow>();
    public bool Migrated => Imports.Any(i => i.Kind == "migration" && i.Outcome == "Imported");
    public string? Error { get; private set; }
    /// The row-level report of a refused file, or the counted result of an import.
    public IReadOnlyList<CmdbCsvIssue> FileErrors { get; private set; } = Array.Empty<CmdbCsvIssue>();
    public IReadOnlyList<CmdbCsvIssue> FileWarnings { get; private set; } = Array.Empty<CmdbCsvIssue>();
    public CmdbImportResult? Result { get; private set; }
    public bool ReadOnly => CmdbSources.IsReadOnly(Source);

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    private async Task LoadAsync(CancellationToken ct)
    {
        try { CiTable = await _ciTable.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the SQL CI table could not be read");
            CiTableError = "The SQL CI table could not be read: " + ex.Message;
        }
        try
        {
            Schema = await _store.SchemaAsync(ct);
            Source = (await _store.ActiveSourceAsync(ct)).Source;
            if (!Schema.HasCmdb) { Error = "This database has no CMDB tables yet. Run the Pro settings schema (setup) once; the CMDB then appears here."; return; }
            Services = await _store.ServicesAsync(Source, Retired, ct);
            Imports = await _store.ImportsAsync(20, ct);
            if (!Exporting) await LoadTablesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the CMDB could not be read");
            Error = "The CMDB could not be read from the Pro database: " + ex.Message;
        }
    }

    // ---- #589 the services as the shared data table: every field, the source file's other columns, the exports ----------

    protected override Task LoadForExportAsync(CancellationToken ct) => LoadAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables() => [ServicesTable(Services, "services", "cmdb-services", "CMDB services")];

    /// The CMDB services as a data table (also the service page's own row and the not-seen page reuse the columns).
    public static SI.Management.Web.Columns.DataTable ServicesTable(IReadOnlyList<CmdbService> services, string id, string view, string title)
    {
        static CmdbService S(object o) => (CmdbService)o;
        var rows = services.Cast<object>().ToList();
        SI.Management.Web.Columns.DataColumn[] own =
        [
            new("ServiceNumber", "Number", o => S(o).Number, Link: o => "/Cmdb/Service?id=" + S(o).ServiceId),
            new("ServiceName", "Name", o => S(o).Name),
            new("ExternalId", "CMDB id (sys_id)", o => S(o).ExternalId),
            new("Description", "Description", o => S(o).Description),
            new("Owner", "Owner", o => S(o).Owner),
            new("OwnerMail", "Owner e-mail", o => S(o).OwnerMail),
            new("Criticality", "Criticality", o => S(o).Criticality),
            new("DataSensitivity", "Data sensitivity", o => S(o).DataSensitivity),
            new("Environment", "Environment", o => S(o).Environment),
            new("Department", "Department", o => S(o).Department),
            new("Assets", "Assets", o => S(o).Assets, Number: true),
            new("Status", "Status", o => S(o).Retired ? "retired" : "active"),
            new("Source", "Source", o => CmdbSources.Label(S(o).Source)),
            new("CreatedAt", "Created", o => S(o).CreatedAt),
            new("CreatedBy", "Created by", o => S(o).CreatedBy),
            new("UpdatedAt", "Changed", o => S(o).UpdatedAt),
            new("UpdatedBy", "Changed by", o => S(o).UpdatedBy),
            new("RetiredAt", "Retired", o => S(o).RetiredAt),
            new("RetiredBy", "Retired by", o => S(o).RetiredBy),
            new("RetireReason", "Why retired", o => S(o).RetireReason),
        ];
        var t = new SI.Management.Web.Columns.DataTable
        {
            Id = id, View = view, Title = title, Rows = rows, Marker = "data-services",
            RowAttributes = o => new Dictionary<string, string?> { ["data-service"] = S(o).Number },
            // then the CMDB source's other columns under their own names; one named like a column above ("Status") says where it is from
            Columns = [.. own, .. SI.Management.Web.Columns.DataTable.Bag(rows, o => S(o).Extra(), "Csv", taken: own.Select(c => c.Label), what: "CMDB source")],
        };
        t.Html["Status"] = o => S(o).Retired
            ? SI.Management.Web.Columns.DataCellHtml.Badges(("", "retired " + Fmt.When(S(o).RetiredAt)))
            : SI.Management.Web.Columns.DataCellHtml.Badges(("good", "active"));
        return t;
    }

    // ---- add a service (Admin, SecurityInsight's own CMDB) ----
    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Description { get; set; }
    [BindProperty] public string? Owner { get; set; }
    [BindProperty] public string? OwnerMail { get; set; }
    [BindProperty] public string? Criticality { get; set; }
    [BindProperty] public string? DataSensitivity { get; set; }
    [BindProperty] public string? Environment { get; set; }
    [BindProperty] public string? Department { get; set; }
    [BindProperty] public string? Reason { get; set; }

    [SI.Management.Web.Audit.Audited("cmdb.service.add")]
    public async Task<IActionResult> OnPostAddAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (r, svc) = await _store.CreateAsync(new CmdbServiceInput(Name ?? "", Description, Owner, OwnerMail, Criticality, DataSensitivity, Environment, Department), User.ChangeName(), Reason, ct);
        TempData["toast"] = r.Status == WriteStatus.Saved ? r.Message : "Not added: " + r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        return svc is not null ? RedirectToPage("Service", new { id = svc.ServiceId }) : RedirectToPage();
    }

    // ---- files: the external CSV (snapshot) and the one-time migration of a v2.2 CMDB.csv ----
    [BindProperty] public IFormFile? ServicesFile { get; set; }
    [BindProperty] public IFormFile? MembersFile { get; set; }

    private static async Task<string?> ReadAsync(IFormFile? f, CancellationToken ct)
    {
        if (f is null || f.Length == 0) return null;
        if (f.Length > CmdbCsv.MaxBytes) throw new InvalidDataException($"{f.FileName} is larger than {CmdbCsv.MaxBytes / 1024 / 1024} MB");
        using var rd = new StreamReader(f.OpenReadStream(), System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return await rd.ReadToEndAsync(ct);
    }

    /// Upload a CMDB.csv (+ memberships) as the External-CSV CMDB's new snapshot.
    [SI.Management.Web.Audit.Audited("cmdb.import.upload")]
    public Task<IActionResult> OnPostUploadAsync(CancellationToken ct) => ImportFileAsync(CmdbSources.ExternalCsv, "csv-upload", ct);

    /// Import a v2.2 CMDB.csv ONCE into SecurityInsight's own CMDB.
    [SI.Management.Web.Audit.Audited("cmdb.import.migrate")]
    public Task<IActionResult> OnPostMigrateAsync(CancellationToken ct) => ImportFileAsync(CmdbSources.SI, "migration", ct);

    private async Task<IActionResult> ImportFileAsync(string target, string kind, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        await LoadAsync(ct);
        if (Error is not null) return Page();
        if (kind == "migration" && ReadOnly)
        {
            Error = $"The CMDB source is {CmdbSources.Label(Source)}. A CMDB.csv is migrated into SecurityInsight's own CMDB only while that is the authoritative source -- switch the CMDB source first.";
            return Page();
        }
        string? services, members;
        try { services = await ReadAsync(ServicesFile, ct); members = await ReadAsync(MembersFile, ct); }
        catch (InvalidDataException ex) { Error = ex.Message; return Page(); }
        if (services is null) { Error = "Choose the CMDB.csv file to import."; return Page(); }
        var parsed = CmdbCsv.Parse(services, members);
        FileErrors = parsed.Errors; FileWarnings = parsed.Warnings;
        if (!parsed.Ok) return Page();
        var origin = ServicesFile!.FileName + (MembersFile is { Length: > 0 } ? " + " + MembersFile.FileName : "");
        try
        {
            Result = await _store.ImportAsync(target, kind, origin, CmdbCsv.Sha256(services, members), CmdbCsv.ToPayload(parsed, members is not null), User.ChangeName(),
                kind == "migration" ? "one-time import of the v2.2 CMDB.csv" : "CMDB.csv uploaded in the web app", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the CMDB import failed");
            Error = "The import failed and nothing was written: " + ex.Message;
            return Page();
        }
        await LoadAsync(ct);
        return Page();
    }
}
