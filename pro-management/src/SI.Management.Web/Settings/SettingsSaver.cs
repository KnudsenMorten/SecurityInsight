using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Settings;

/// The outcome of one save of a set of settings: whether everything posted was written, the words to show, the
/// refusals per setting, and per written setting what the page shows now (text, version, set).
public sealed record SettingsSaveResult(bool Ok, string Message, IReadOnlyDictionary<string, string> Errors, IReadOnlyDictionary<string, object> Fields, int Saved);

/// <summary>
/// THE ONE SAVE of a group of settings -- Settings &gt; a card's Save AND a Get Started step (#446, operator: "all fields
/// must be in the get started, writing to the same setting"). The form carries per field v:Name (the value; a switch
/// posts "false" then "true" when ticked), ver:Name (the RowVersion read), scope:Name and reset:Name; a field whose input
/// was disabled posts nothing and is left alone. Every field is planned and validated first; if any is refused, nothing
/// is written. Each write goes through <see cref="SettingsWriter"/> (validation, the version check, the change log) and
/// the request's audit row records before / after.
/// </summary>
public sealed class SettingsSaver
{
    private readonly SettingsCatalog _catalog;
    private readonly ISettingsStoreReader _reader;
    private readonly SettingsWriter _writer;

    public SettingsSaver(SettingsCatalog catalog, ISettingsStoreReader reader, SettingsWriter writer) { _catalog = catalog; _reader = reader; _writer = writer; }

    public async Task<SettingsSaveResult> SaveAsync(IFormCollection form, IEnumerable<string> settingNames, ClaimsPrincipal user, string auditTarget, CancellationToken ct)
    {
        var names = settingNames.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var (rows, _) = await _reader.ReadSettingsAsync(ct);
        var errors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var plans = new List<(CatalogSetting S, SettingWrite W, SettingRow? Current)>();
        foreach (var name in names)
        {
            var s = _catalog.Find(name);
            if (s is null) { errors[name] = $"'{name}' is not a known setting"; continue; }
            var posted = form.ContainsKey("v:" + s.Name) || form["reset:" + s.Name] == "1";
            if (!posted) continue;
            if (s.NeedsSuperAdmin && !user.IsSuperAdmin()) { errors[s.Name] = "SuperAdmin required to change it"; continue; }
            if (s.SetupOnly) { errors[s.Name] = CatalogSetting.SetupOnlyNote + " -- it cannot be changed here"; continue; }
            var post = new FieldPost(s.Name, form["v:" + s.Name].LastOrDefault(), form["reset:" + s.Name] == "1", form["ver:" + s.Name].ToString(), form["scope:" + s.Name].ToString());
            var scope = string.IsNullOrWhiteSpace(post.Scope) ? s.DefaultScope : post.Scope.Trim();
            var current = rows.FirstOrDefault(r => r.Name.Equals(s.Name, StringComparison.OrdinalIgnoreCase) && r.Scope == scope);
            var (write, error) = SettingsForm.Plan(s, post, current);
            if (error is not null) { errors[s.Name] = error; continue; }
            if (write is null) continue;
            var (_, refusal) = _writer.Prepare(write);
            if (refusal is not null) { errors[s.Name] = refusal; continue; }
            plans.Add((s, write, current));
        }

        var audit = AuditScope.Current;
        if (audit is not null)
        {
            audit.Target = auditTarget + (plans.Count > 0 ? ", names=" + string.Join(" ", plans.Select(p => p.S.Name)) : "");
            audit.Reason = SettingsForm.Reason;
        }
        var results = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        if (errors.Count > 0)
        {
            var why = "Nothing was saved: " + string.Join("; ", errors.Select(e => (_catalog.Find(e.Key)?.Title ?? e.Key) + " -- " + e.Value));
            audit?.Set(AuditOutcomes.Refused, why);
            return new SettingsSaveResult(false, why, errors, results, 0);
        }
        if (plans.Count == 0) return new SettingsSaveResult(true, "Nothing changed.", errors, results, 0);

        var before = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var after = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var saved = new List<string>();
        var problems = new List<string>();
        foreach (var (s, w, current) in plans)
        {
            var r = await _writer.WriteAsync(w, user.ChangeName(), ct);
            var (prepared, _) = _writer.Prepare(w);
            if (r.Status == WriteStatus.Saved && prepared is not null)
            {
                saved.Add(s.Title);
                before[s.Name] = current is null ? "(default)" : SettingsForm.Display(current.ValueJson, current.KeyVaultSecretName);
                after[s.Name] = w.Action == "Reset" ? "(default)" : SettingsForm.Display(prepared.ValueJson, prepared.KeyVaultSecretName);
                results[s.Name] = new { text = SettingsForm.ShownAfter(s, prepared), version = w.Action == "Reset" ? "" : r.NewVersion?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "", set = w.Action != "Reset" };
            }
            else
            {
                errors[s.Name] = r.Status == WriteStatus.Stale ? "changed by someone else since you opened the page -- reload it" : r.Message;
                problems.Add(s.Title + " -- " + errors[s.Name]);
            }
        }
        if (audit is not null)
        {
            audit.BeforeJson = JsonSerializer.Serialize(before);
            audit.AfterJson = JsonSerializer.Serialize(after);
            if (saved.Count == 0) audit.Set(AuditOutcomes.Refused, string.Join("; ", problems));
        }
        var message = (saved.Count > 0 ? "Saved: " + string.Join(", ", saved) + ". It applies from the next run." : "")
            + (problems.Count > 0 ? (saved.Count > 0 ? " " : "") + "Not saved: " + string.Join("; ", problems) : "");
        return new SettingsSaveResult(problems.Count == 0, message, errors, results, saved.Count);
    }
}

/// One field for the shared editor partial (Pages/Shared/_SettingField.cshtml): the field, whether this person may
/// change SuperAdmin-only settings, and the refusal to show under it (a Get Started step re-shown after a refused save).
/// Unavailable: the field cannot be changed here now, said in one line under it (the detailed Excel switch above the size a
/// workbook holds -- DetailedWorkbookLimit); a switch stored on is shown as on but not applied.
public sealed record SettingFieldView(SettingField F, bool CanSuperAdmin, string? Error = null, string? ShowWhen = null, bool Hidden = false, string? Unavailable = null, string? Label = null);
// ShowWhen = "Name=value": the field shows only while that setting's choice is that value (wwwroot/js/app/show-when.js)
// Label (#633): the label this page gives the field (null = the catalog's title)
