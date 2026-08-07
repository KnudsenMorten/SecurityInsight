namespace SIAnalyzer.Core.Governance;

/// <summary>
/// The enable-flags for governance WRITE/sync surfaces - and the HARD LOCK that the
/// no-auto-revoke rule demands.
///
/// CRITICAL (operator directive, Phase 6): every governance write/sync surface that touches a
/// PLATFORM (Defender-for-Cloud / Azure Policy / Defender XDR exemption sync - which
/// suppresses/removes findings on the platform) MUST ship OFF by default AND be impossible to
/// enable until it is fully tested. A build must NOT ship an enable-able governance platform
/// write.
///
/// So the platform-sync capability here is not merely "default false" - it is <see
/// cref="PlatformSyncLocked"/> = true (a compile-time constant). Even if an operator sets
/// <c>SIAnalyzer:Governance:EnablePlatformSync=true</c> in config, <see cref="PlatformSyncEnabled"/>
/// still returns false while the lock holds. The GUI renders the sync controls VISIBLE but
/// dimmed/disabled with a "disabled until tested" note; the server-side write path also
/// refuses to act while locked. Flipping the lock to false is a deliberate, reviewed code
/// change made only after the hosted sync test passes - never a config toggle.
///
/// Note the asymmetry the requirement calls out: DISPLAYING an accepted/exempt state is a
/// read and is always allowed; recording a risk-accept comment / exemption in SIA's OWN store
/// is a local write (no platform touched) and is allowed when <see
/// cref="LocalRegisterEnabled"/> is on. Only the PLATFORM-writing sync is the gated part.
/// </summary>
public sealed class GovernanceCapabilities
{
    /// <summary>
    /// Compile-time lock on the platform-exemption-sync write path. TRUE = the sync can NOT
    /// be enabled by any config in this build (the no-auto-revoke guarantee). Only a reviewed
    /// code change flips this to false, and only after the hosted sync test passes.
    /// </summary>
    public const bool PlatformSyncLocked = true;

    /// <summary>
    /// Operator REQUEST to enable platform sync (from config). It is only a request: the
    /// effective state is <see cref="PlatformSyncEnabled"/>, which the lock can override.
    /// Defaults OFF.
    /// </summary>
    public bool EnablePlatformSync { get; set; }

    /// <summary>
    /// Whether SIA's OWN governance register accepts local writes (risk-accept comments +
    /// recording exemptions WITHOUT platform sync). These never touch MDE/Entra/ARM. Defaults
    /// OFF too, so a fresh deploy is fully read-only until the operator opts in; turning it on
    /// is safe because no platform is written.
    /// </summary>
    public bool LocalRegisterEnabled { get; set; }

    /// <summary>
    /// The EFFECTIVE platform-sync state. False whenever the lock holds, regardless of config.
    /// This is the single source of truth the write path and the GUI both honour.
    /// </summary>
    public bool PlatformSyncEnabled => !PlatformSyncLocked && EnablePlatformSync;

    /// <summary>A human-readable reason the platform-sync control is disabled, for the GUI
    /// "disabled until tested" note.</summary>
    public string PlatformSyncDisabledReason =>
        PlatformSyncLocked
            ? "Disabled until tested - platform exemption sync (Defender for Cloud / Azure Policy / Defender XDR) is locked off in this build and cannot be enabled. It suppresses findings on the platform, so it stays off until the hosted sync test passes."
            : EnablePlatformSync
                ? "Enabled."
                : "Off - set SIAnalyzer:Governance:EnablePlatformSync=true to enable (the lock is already lifted in this build).";
}
