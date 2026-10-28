using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// <summary>
/// The two things SecurityInsight Pro does with Invardia by itself -- the automatic licence request and the Pro updates
/// from Invardia. Both are ON by default (owner decision 2026-10-05, the same treatment as the status reports) and the
/// customer switches them off with a solution-wide setting row. The updater job reads the same rows
/// (engine/_shared/SI-ProAutomation.ps1); this page only says which are off.
/// </summary>
public static class ProAutoSwitches
{
    public const string LicenceRequest = "SI_LicenseRequest_Auto";
    public const string InvardiaUpdates = "SI_InvardiaUpdate_Enabled";

    /// On unless the solution-wide row says off (false / "false" / 0 / "off" / "no"). No row, or a value that is not
    /// an on/off word, keeps the default: on.
    public static bool IsOn(IEnumerable<SettingRow> rows, string name)
    {
        var row = rows.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)
                                           && string.Equals(r.Scope, "solution", StringComparison.OrdinalIgnoreCase));
        if (row?.ValueJson is null) return true;
        var v = row.ValueJson.Trim().Trim('"').Trim().ToLowerInvariant();
        return v is not ("false" or "0" or "off" or "no" or "disabled");
    }
}
