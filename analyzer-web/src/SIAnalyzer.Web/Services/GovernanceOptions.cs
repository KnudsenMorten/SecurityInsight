using SIAnalyzer.Core.Governance;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// Bound from "SIAnalyzer:Governance". Maps config to the Core <see cref="GovernanceCapabilities"/>
/// and says WHERE the register is stored. Holds NO secrets - the table is reached with the app's
/// Managed Identity, never a connection string with a key.
///
/// The platform-sync flag is HARD-LOCKED off in Core (the no-auto-revoke rule), so setting
/// EnablePlatformSync=true here is only a request that the lock overrides.
/// </summary>
public sealed class GovernanceOptions
{
    public const string SectionName = "SIAnalyzer:Governance";

    /// <summary>
    /// Allow local risk-accept comments + recording exemptions in SIA's own store (no platform
    /// written). ON by default (operator decision 2026-08-05: the register must be active).
    /// These writes never touch MDE/Entra/ARM - only SIA's own table - which is why this can
    /// default on while the PLATFORM sync stays locked. Set false for a fully read-only deploy.
    /// The deploy sets it explicitly anyway, so the live value is visible in
    /// <c>az containerapp show</c> rather than inferred from a code default (the #3 lesson).
    /// </summary>
    public bool LocalRegisterEnabled { get; set; } = true;

    /// <summary>REQUEST to enable platform exemption sync. OFF by default and overridden by the
    /// compile-time lock in Core until the hosted sync test passes.</summary>
    public bool EnablePlatformSync { get; set; }

    /// <summary>
    /// The Azure Table Storage endpoint holding the register, e.g.
    /// <c>https://stsecurityinsight.table.core.windows.net</c>. When set, records are DURABLE and
    /// shared across replicas. When empty, SIA falls back to the in-memory register and SAYS SO on
    /// the governance page - it never presents a volatile list as a register of record.
    /// </summary>
    public string TableEndpoint { get; set; } = "";

    /// <summary>Table name inside that account. One table, three partitions.</summary>
    public string TableName { get; set; } = "sigovernance";

    public GovernanceCapabilities ToCapabilities() => new()
    {
        LocalRegisterEnabled = LocalRegisterEnabled,
        EnablePlatformSync = EnablePlatformSync,
    };
}
