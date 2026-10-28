using System.Text.Json;
using SI.Management.Web.Settings;

namespace SI.Management.Web.GetStarted;

/// <summary>
/// The web app's own settings behind a Get Started step that SecurityInsight cannot check itself (#446): the step saves
/// the confirmation as a setting -- the same cfg.Setting row the Settings page shows -- and counts it. None today: the
/// Conditional Access confirmation step was removed (operator 2026-10-09: "what is this, i didnt ask for that").
/// </summary>
public static class GetStartedSettings
{
    public static readonly IReadOnlyList<CatalogSetting> Catalog = [];
}
