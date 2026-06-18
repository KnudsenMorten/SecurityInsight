namespace Sia.Core.Configuration;

/// <summary>
/// The outcome of resolving which data source SIA should read: a live Log Analytics
/// workspace (the internal-env base by default) or the synthetic demo snapshot.
/// </summary>
public sealed record WorkspaceResolution(bool IsLive, bool UseDemoData, string? WorkspaceId, string Source);

/// <summary>
/// Decides whether SIA reads a LIVE workspace or DEMO data. The internal SI workspace
/// is the default base: a configured workspace id =&gt; live; an explicit demo request or
/// no configured workspace =&gt; demo (with operator guidance). Read-only either way.
/// </summary>
public static class WorkspaceResolver
{
    public static WorkspaceResolution Resolve(string? workspaceId, bool forceDemo)
    {
        if (forceDemo)
        {
            return new WorkspaceResolution(IsLive: false, UseDemoData: true, WorkspaceId: null,
                Source: "Demo data forced (UseDemoData) - no live workspace queried.");
        }

        if (string.IsNullOrWhiteSpace(workspaceId))
        {
            return new WorkspaceResolution(IsLive: false, UseDemoData: true, WorkspaceId: null,
                Source: "No workspace configured - Set Sia:WorkspaceId to the internal base workspace to read live data; using demo data for now.");
        }

        return new WorkspaceResolution(IsLive: true, UseDemoData: false, WorkspaceId: workspaceId,
            Source: "Live: configured Log Analytics workspace (internal env base).");
    }
}
