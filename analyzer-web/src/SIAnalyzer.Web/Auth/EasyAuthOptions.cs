namespace SIAnalyzer.Web.Auth;

/// <summary>
/// Bound from the "SIAnalyzer:Auth" config section. Controls the in-app Easy-Auth gate that is
/// defense-in-depth ON TOP of the platform's Entra Easy Auth (which already terminates
/// sign-in in front of the container). Holds NO secrets.
/// </summary>
public sealed class EasyAuthOptions
{
    public const string SectionName = "SIAnalyzer:Auth";

    /// <summary>
    /// When true, the app REQUIRES a valid Easy Auth client principal
    /// (<c>X-MS-CLIENT-PRINCIPAL</c>) on EVERY request except <see cref="AnonymousPaths"/>
    /// and the always-open liveness probe - the same authenticated principal as the UI -
    /// rejecting anonymous callers with 401 even if the platform gate is bypassed.
    /// <para>
    /// DEFAULTS TO <c>true</c> (fail-closed), operator directive 2026-08-05: "we need that
    /// this page is authenticated by default". It previously defaulted to <c>false</c> so
    /// local/demo runs worked - but <c>Deploy-SIAnalyzer.ps1</c> never set it either
    /// (verified: zero references), so the gate that existed was OFF in production and
    /// protected nothing. Local development opts out via
    /// <c>appsettings.Development.json</c>, which never ships to the hosted environment.
    /// </para>
    /// </summary>
    public bool RequireClientPrincipal { get; set; } = true;

    /// <summary>
    /// Routes served ANONYMOUSLY even when the gate is on - for management dashboards and
    /// wall-mounted info screens, which cannot sign in.
    /// <para>
    /// DEFAULTS TO EMPTY (operator 2026-08-05: "start with empty exemption list, i will add
    /// screens later"), so nothing is anonymous until it is explicitly named here. Matching
    /// is a case-insensitive path-prefix test.
    /// </para>
    /// <para>
    /// NEVER add a write endpoint, <c>/api/query</c>, <c>/api/adhoc</c>,
    /// <c>/api/email/send</c> or <c>/mcp</c> here. This is for read-only dashboard views,
    /// and only on a network that is not reachable from the internet.
    /// </para>
    /// </summary>
    public string[] AnonymousPaths { get; set; } = System.Array.Empty<string>();
}
