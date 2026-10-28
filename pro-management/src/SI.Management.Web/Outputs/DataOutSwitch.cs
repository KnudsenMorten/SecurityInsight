using SI.Management.Core.ProData;
using SI.Management.Web.Pages.Reports;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Outputs;

/// <summary>
/// #903 (owner 2026-10-26: "if active they should be part of the data out for both cmdb and vulnerability"): when a staged
/// "Switch on" of the ServiceNow data-out connector is committed, its outputs are switched on in SI_DataOut_Outputs -- the
/// same version-checked settings write (with its cfg.ChangeLog row) as Connectors &gt; Fields sent's own switch, every other
/// output kept as it runs now. SI_DataOut_Outputs stays per output: either can be switched off again on its own.
/// </summary>
public sealed class DataOutSwitch(SettingsCatalog catalog, ISettingsStoreReader reader, SettingsWriter writer, ILogger<DataOutSwitch> log)
{
    /// (true, what was done) or (false, why not) -- in plain words.
    public async Task<(bool Ok, string Message)> SwitchOnAsync(IReadOnlyCollection<string> outputs, string by, string reason, CancellationToken ct)
    {
        var setting = catalog.Find(OutputFieldsModel.OutputsSetting);
        if (setting is null) return (false, "the outputs could not be switched on: this install's settings catalog has no " + OutputFieldsModel.OutputsSetting);
        try
        {
            var rows = (await reader.ReadSettingsAsync(ct)).Rows;
            var row = rows.Where(r => r.Name.Equals(OutputFieldsModel.OutputsSetting, StringComparison.OrdinalIgnoreCase)).OrderBy(r => r.Scope == "global" ? 0 : 1).FirstOrDefault();
            var text = row is null ? null : SettingJson.ToFormText(row.ValueJson);
            var value = text;
            foreach (var o in outputs) value = OutputFieldsModel.Switched(OutputMapRules.Catalog, value, o, true);
            var labels = string.Join(" and ", outputs.Select(o => ServiceNowOutputs.Of(o)?.Label ?? o));
            if (OutputFieldsModel.OnOutputs(OutputMapRules.Catalog, text).IsSupersetOf(outputs)) return (true, labels + " " + (outputs.Count == 1 ? "was" : "were") + " on already");
            var scope = row?.Scope ?? setting.DefaultScope;
            var w = value is null
                ? new SettingWrite(setting.Name, scope, "Reset", null, null, row?.Version, reason)
                : new SettingWrite(setting.Name, scope, "Set", SettingJson.FromForm(setting, value), null, row?.Version, reason);
            var r = await writer.WriteAsync(w, by, ct);
            return r.Status == WriteStatus.Saved
                ? (true, $"{labels} switched on ({OutputFieldsModel.OutputsSetting} = {value ?? "the defaults"})")
                : (false, $"{labels} could not be switched on ({r.Message}) -- switch them on on Connectors > Fields sent");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the ServiceNow outputs could not be switched on");
            return (false, "the outputs could not be switched on (" + ex.Message + ") -- switch them on on Connectors > Fields sent");
        }
    }
}
