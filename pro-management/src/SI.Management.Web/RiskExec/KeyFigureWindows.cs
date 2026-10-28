namespace SI.Management.Web.RiskExec;

/// <summary>
/// #859 NO STATIC VALUES (owner 2026-10-21: "do we have static values in the code ?" / "why not use the settings values
/// (customer specific)"): the windows the key figures count over are settings of the install, read by ONE reader
/// (Get-SIKeyFigureWindowSettings, engine/pro-data/_shared/SI-DataKeyFigures.ps1) and written with the figures as meta
/// "window" rows -- the web app shows the value of the collection it shows (<see cref="ExecutiveFigures.Window"/>).
/// These are the keys of those rows, the settings behind them and their shipped defaults (today's values): a collection
/// figured before the windows were recorded was figured with exactly these. A test holds them to the engine's defaults
/// and the settings catalog.
/// </summary>
public static class KeyFigureWindows
{
    public const string RecentDays = "recent_days";
    public const string MeanTimeToFixDays = "mttr_days";
    public const string StaleAdminDays = "stale_admin_days";
    public const string CveAgeBand = "cve_age_band";

    /// The meta window key -> (the setting, its shipped default).
    public static readonly IReadOnlyDictionary<string, (string Setting, int Default)> All = new Dictionary<string, (string, int)>
    {
        [RecentDays] = ("SI_KeyFigures_RecentDays", 30),
        [MeanTimeToFixDays] = ("SI_KeyFigures_MeanTimeToFixDays", 90),
        [StaleAdminDays] = ("SI_KeyFigures_StaleAdminDays", 90),
    };

    /// The CVE age bands' setting and its shipped default.
    public const string CveAgeBandsSetting = "SI_KeyFigures_CveAgeBands";
    public static readonly IReadOnlyList<int> DefaultCveAgeBands = [30, 60, 90];

    /// A window's shipped default (0 for an unknown key).
    public static int Default(string key) => All.TryGetValue(key, out var w) ? w.Default : 0;
}
